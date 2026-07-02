import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  createOidcProdAuthPreflightManifest,
  evaluateOidcProdAuthPreflight,
  main,
  parseArgs,
  redactUrlForEvidence,
  verifyJwksFetchRedirectPolicyOffline,
} from '../../scripts/oidc-prod-auth-preflight.mjs';

const tempDirs = [];
const envSnapshot = { ...process.env };

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-oidc-preflight-'));
  tempDirs.push(dir);
  return dir;
}

function baseProductionOidcEnv(overrides = {}) {
  return {
    NODE_ENV: 'production',
    ASTRANULL_AUTH_MODE: 'oidc-jwt',
    ASTRANULL_OIDC_ISSUER: 'https://idp.example/oauth2/default',
    ASTRANULL_OIDC_AUDIENCE: 'astranull-api',
    ASTRANULL_OIDC_JWKS_URL:
      'https://idp.example/oauth2/default/v1/keys?client_secret=supersecret',
    ASTRANULL_SECRET_ENCRYPTION_KEY: randomBytes(32).toString('base64'),
    ASTRANULL_DATABASE_URL: 'postgresql://user:secret@db.example:5432/astranull',
    ASTRANULL_PROBE_WORKER_SECRET: 'test-probe-worker-secret-32-chars!!',
    ...overrides,
  };
}

function checkById(checks, id) {
  const check = checks.find((entry) => entry.id === id);
  assert.ok(check, `missing check ${id}`);
  return check;
}

afterEach(() => {
  restoreEnv();
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('oidc production auth preflight utility', () => {
  it('parses defaults and explicit CLI arguments', () => {
    assert.deepEqual(parseArgs([]), {
      out: 'output/oidc-prod-auth-preflight.json',
      help: false,
    });
    assert.deepEqual(parseArgs(['--out', 'evidence.json']), {
      out: 'evidence.json',
      help: false,
    });
    assert.throws(() => parseArgs(['--unknown']), /Unknown argument/);
  });

  it('passes for a safe production OIDC configuration', () => {
    const env = baseProductionOidcEnv();
    const evaluation = evaluateOidcProdAuthPreflight(env);
    assert.equal(evaluation.ok, true);
    assert.equal(checkById(evaluation.checks, 'auth_mode_oidc_jwt').ok, true);
    assert.equal(checkById(evaluation.checks, 'oidc_mfa_enforced').ok, true);
    assert.equal(checkById(evaluation.checks, 'negative_dev_headers_refused').ok, true);
    assert.equal(checkById(evaluation.checks, 'negative_signed_session_refused').ok, true);
    assert.equal(checkById(evaluation.checks, 'negative_http_jwks_refused').ok, true);
    assert.equal(evaluation.auth_posture.oidc.require_mfa, true);
  });

  it('fails when production would accept dev-headers auth', () => {
    const env = baseProductionOidcEnv({ ASTRANULL_AUTH_MODE: 'dev-headers' });
    const evaluation = evaluateOidcProdAuthPreflight(env);
    assert.equal(evaluation.ok, false);
    assert.equal(checkById(evaluation.checks, 'auth_mode_oidc_jwt').ok, false);
    assert.equal(checkById(evaluation.checks, 'production_runtime_config_loads').ok, false);
    assert.equal(checkById(evaluation.checks, 'negative_dev_headers_refused').ok, true);
  });

  it('fails when JWKS URL is HTTP in production posture', () => {
    const env = baseProductionOidcEnv({
      ASTRANULL_OIDC_JWKS_URL: 'http://idp.example/jwks',
    });
    const evaluation = evaluateOidcProdAuthPreflight(env);
    assert.equal(evaluation.ok, false);
    assert.equal(checkById(evaluation.checks, 'oidc_jwks_https').ok, false);
    assert.equal(checkById(evaluation.checks, 'production_runtime_config_loads').ok, false);
    assert.equal(checkById(evaluation.checks, 'negative_http_jwks_refused').ok, true);
  });

  it('fails when issuer, audience, or MFA posture is missing', () => {
    const missingIssuer = evaluateOidcProdAuthPreflight(
      baseProductionOidcEnv({ ASTRANULL_OIDC_ISSUER: '' }),
    );
    assert.equal(missingIssuer.ok, false);
    assert.equal(checkById(missingIssuer.checks, 'oidc_issuer_configured').ok, false);

    const missingAudience = evaluateOidcProdAuthPreflight(
      baseProductionOidcEnv({ ASTRANULL_OIDC_AUDIENCE: '' }),
    );
    assert.equal(missingAudience.ok, false);
    assert.equal(checkById(missingAudience.checks, 'oidc_audience_configured').ok, false);

    const mfaDisabled = evaluateOidcProdAuthPreflight(
      baseProductionOidcEnv({ ASTRANULL_OIDC_REQUIRE_MFA: '0' }),
    );
    assert.equal(mfaDisabled.ok, false);
    assert.equal(checkById(mfaDisabled.checks, 'oidc_mfa_enforced').ok, false);
  });

  it('redacts URL query strings and database secrets from manifest output', () => {
    const env = baseProductionOidcEnv();
    const manifest = createOidcProdAuthPreflightManifest({
      env,
      createdAt: '2026-07-02T00:00:00.000Z',
    });
    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('client_secret=supersecret'), false);
    assert.equal(blob.includes('postgresql://user:secret@db.example'), false);
    assert.match(manifest.auth_posture.oidc.jwks_url_redacted, /\?\[REDACTED\]$/);
    assert.equal(redactUrlForEvidence('https://user:pass@idp.example/jwks?token=abc'), 'https://idp.example/jwks?[REDACTED]');
  });

  it('creates a metadata-only output manifest with offline caveats', () => {
    const manifest = createOidcProdAuthPreflightManifest({
      env: baseProductionOidcEnv(),
      createdAt: '2026-07-02T00:00:00.000Z',
    });
    assert.equal(manifest.schema_version, 1);
    assert.equal(manifest.artifact_type, 'oidc_production_auth_preflight');
    assert.equal(manifest.mode, 'offline');
    assert.ok(Array.isArray(manifest.checks) && manifest.checks.length > 0);
    assert.match(manifest.caveats.join(' '), /does not fetch JWKS/i);
    assert.equal(verifyJwksFetchRedirectPolicyOffline().ok, true);
  });

  it('writes output and returns nonzero when required checks fail', async () => {
    const dir = tempDir();
    const out = path.join(dir, 'preflight.json');
    Object.assign(process.env, baseProductionOidcEnv({ ASTRANULL_OIDC_ISSUER: '' }));

    const failCode = await main(['--out', out]);
    assert.equal(failCode, 1);
    assert.equal(existsSync(out), true);
    const failedManifest = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(failedManifest.ok, false);

    Object.assign(process.env, baseProductionOidcEnv());
    const passCode = await main(['--out', out]);
    assert.equal(passCode, 0);
    const passedManifest = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(passedManifest.ok, true);
  });
});