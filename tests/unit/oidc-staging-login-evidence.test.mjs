import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  OIDC_STAGING_LOGIN_REQUIRED_SCENARIOS,
  collectForbiddenStringPatterns,
  createOidcStagingLoginEvidenceManifest,
  evaluateOidcStagingLoginOffline,
  main,
  parseArgs,
  validateOidcStagingLoginEvidence,
} from '../../scripts/oidc-staging-login-evidence.mjs';

const tempDirs = [];
const envSnapshot = { ...process.env };

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-oidc-staging-login-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function passedScenario(scenarioId, overrides = {}) {
  const roleByScenario = {
    admin_role_login: 'admin',
    engineer_role_login: 'engineer',
    viewer_role_login: 'viewer',
    soc_role_login: 'soc',
  };
  return {
    scenario_id: scenarioId,
    status: 'passed',
    evidence_uri: `evidence://oidc/staging-login/${scenarioId}`,
    owner: 'security-oncall',
    completed_at: '2026-07-03T12:00:00.000Z',
    api_probe_reference: `probe://oidc/staging-login/${scenarioId}`,
    mapped_role: roleByScenario[scenarioId] ?? null,
    mapped_tenant_reference: scenarioId === 'tenant_claim_mapping' ? 'tenant://staging/ten_demo' : null,
    ...overrides,
  };
}

function validEvidence(overrides = {}) {
  return {
    release_id: 'rel_oidc_staging_login_20260703',
    environment: 'staging',
    evidence_uri: 'evidence://oidc/staging-login/matrix',
    signoff: {
      owner: 'security-lead',
      signed_at: '2026-07-03T13:00:00.000Z',
      signoff_reference: 'signoff://security/oidc-staging-login',
    },
    claim_mapping_summary: {
      tenant_claim: 'tenant_id',
      role_claim: 'groups',
      user_claim: 'sub',
      role_prefix: 'astranull-',
      role_map_entry_count: 2,
      mapped_roles: ['owner', 'admin', 'engineer', 'soc', 'auditor', 'viewer'],
    },
    scenarios: OIDC_STAGING_LOGIN_REQUIRED_SCENARIOS.map((scenarioId) => passedScenario(scenarioId)),
    ...overrides,
  };
}

afterEach(() => {
  restoreEnv();
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('oidc staging login evidence validator', () => {
  it('parses CLI arguments', () => {
    assert.deepEqual(parseArgs(['--input', 'evidence.json']), {
      input: 'evidence.json',
      out: 'output/oidc-staging-login-evidence.json',
      releaseId: null,
      validateOnly: false,
      offlineOnly: false,
      help: false,
    });
    assert.deepEqual(
      parseArgs(['--offline-only', '--out', 'out.json', '--release-id', 'rel_x']),
      {
        input: null,
        out: 'out.json',
        releaseId: 'rel_x',
        validateOnly: false,
        offlineOnly: true,
        help: false,
      },
    );
    assert.throws(() => parseArgs([]), /--input is required/);
  });

  it('accepts a valid passed staging login matrix', () => {
    const validation = validateOidcStagingLoginEvidence(validEvidence());
    assert.equal(validation.ok, true);
    assert.equal(validation.overall_status, 'passed');
    assert.deepEqual(validation.missing_scenarios, []);
    assert.deepEqual(validation.failed_scenarios, []);
    assert.deepEqual(validation.forbidden_fields, []);

    const manifest = createOidcStagingLoginEvidenceManifest({ evidence: validEvidence() });
    assert.equal(manifest.artifact_type, 'oidc_staging_login_evidence');
    assert.equal(manifest.validation.ok, true);
    assert.equal(manifest.scenarios.length, OIDC_STAGING_LOGIN_REQUIRED_SCENARIOS.length);
  });

  it('reports missing required scenario coverage', () => {
    const evidence = validEvidence({
      scenarios: OIDC_STAGING_LOGIN_REQUIRED_SCENARIOS
        .filter((id) => id !== 'mfa_login' && id !== 'header_only_negative')
        .map((scenarioId) => passedScenario(scenarioId)),
    });
    const validation = validateOidcStagingLoginEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.equal(validation.overall_status, 'incomplete');
    assert.deepEqual(validation.missing_scenarios, [
      'missing_scenario:mfa_login',
      'missing_scenario:header_only_negative',
    ]);
  });

  it('records validation gaps when a required scenario failed', () => {
    const evidence = validEvidence({
      scenarios: OIDC_STAGING_LOGIN_REQUIRED_SCENARIOS.map((scenarioId) => (
        scenarioId === 'invalid_token_rejected'
          ? passedScenario(scenarioId, { status: 'failed' })
          : passedScenario(scenarioId)
      )),
    });
    const validation = validateOidcStagingLoginEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.equal(validation.overall_status, 'failed');
    assert.deepEqual(validation.failed_scenarios, ['failed_scenario:invalid_token_rejected']);
  });

  it('rejects forbidden nested token and JWT fields', () => {
    const evidence = validEvidence({
      token: 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.sig',
      scenarios: [
        {
          ...passedScenario('admin_role_login'),
          headers: { Authorization: 'Bearer secret' },
        },
        ...OIDC_STAGING_LOGIN_REQUIRED_SCENARIOS
          .filter((id) => id !== 'admin_role_login')
          .map((id) => passedScenario(id)),
      ],
    });
    const validation = validateOidcStagingLoginEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.ok(validation.forbidden_fields.includes('token'));
    assert.ok(validation.forbidden_fields.some((field) => field.includes('headers')));
    assert.ok(collectForbiddenStringPatterns(evidence).some((field) => field.includes('jwt_pattern')));
  });

  it('evaluates offline claim mapping posture from env', () => {
    process.env.NODE_ENV = 'staging';
    process.env.ASTRANULL_AUTH_MODE = 'oidc-jwt';
    process.env.ASTRANULL_OIDC_ISSUER = 'https://idp.staging.example';
    process.env.ASTRANULL_OIDC_AUDIENCE = 'astranull-api';
    process.env.ASTRANULL_OIDC_JWKS_URL = 'https://idp.staging.example/jwks';
    process.env.ASTRANULL_OIDC_TENANT_CLAIM = 'https://astranull.io/tenant_id';
    process.env.ASTRANULL_OIDC_ROLE_CLAIM = 'realm_access.roles';
    process.env.ASTRANULL_OIDC_ROLE_PREFIX = 'astranull-';
    process.env.ASTRANULL_OIDC_ROLE_MAP = 'corp-admin:admin,corp-viewer:viewer';

    const offline = evaluateOidcStagingLoginOffline(process.env);
    assert.equal(offline.ok, true);
    assert.equal(offline.claim_mapping_summary.tenant_claim, 'https://astranull.io/tenant_id');
    assert.equal(offline.claim_mapping_summary.role_claim, 'realm_access.roles');
    assert.equal(offline.claim_mapping_summary.role_prefix, 'astranull-');
    assert.equal(offline.claim_mapping_summary.role_map_entry_count, 2);
  });

  it('validate-only does not write output', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'artifact.json');
    writeJson(input, validEvidence());
    const code = await main(['--input', input, '--out', out, '--validate-only']);
    assert.equal(code, 0);
    assert.equal(existsSync(out), false);
  });

  it('writes a metadata-only artifact from input', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'artifact.json');
    writeJson(input, validEvidence());
    const code = await main(['--input', input, '--out', out, '--release-id', 'rel_cli']);
    assert.equal(code, 0);
    const artifact = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(artifact.artifact_type, 'oidc_staging_login_evidence');
    assert.equal(artifact.release_id, 'rel_oidc_staging_login_20260703');
    const blob = JSON.stringify(artifact);
    assert.equal(blob.includes('eyJhbGciOiJSUzI1NiJ9'), false);
    assert.equal(blob.includes('Authorization'), false);
  });

  it('offline-only emits not_run scenario matrix without input', async () => {
    process.env.NODE_ENV = 'staging';
    process.env.ASTRANULL_AUTH_MODE = 'oidc-jwt';
    process.env.ASTRANULL_OIDC_ISSUER = 'https://idp.staging.example';
    process.env.ASTRANULL_OIDC_AUDIENCE = 'astranull-api';
    process.env.ASTRANULL_OIDC_JWKS_URL = 'https://idp.staging.example/jwks';

    const dir = tempDir();
    const out = path.join(dir, 'offline.json');
    const code = await main(['--offline-only', '--out', out]);
    assert.equal(code, 1);
    const artifact = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(artifact.offline_claim_mapping.ok, true);
    assert.equal(artifact.scenarios.length, OIDC_STAGING_LOGIN_REQUIRED_SCENARIOS.length);
    assert.ok(artifact.scenarios.every((scenario) => scenario.status === 'not_run'));
  });
});