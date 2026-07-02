import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  REQUIRED_NOTIFICATION_CHANNELS,
  createNotificationProviderConfigManifest,
  main,
  parseArgs,
  validateNotificationProviderConfigEvidence,
} from '../../scripts/notification-provider-config-evidence.mjs';
import { redactObject } from '../../src/lib/redact.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-notif-provider-config-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function baseProvider(channel, suffix) {
  return {
    provider_id: `${channel}-${suffix}`,
    channel,
    encrypted_credential_ref_id: `secret://vault/notif/${channel}-${suffix}`,
    rotation_owner: 'platform-ops',
    retry_dlq_policy: {
      max_attempts: 3,
      backoff_summary: 'exponential 30s to 15m with jitter',
      dlq_reference: `dlq://notif/${channel}`,
    },
    tenant_scope: 'tenant_staging_01',
    test_delivery_artifact_ids: [`artifact://notif/${channel}-test-20260702`],
  };
}

function completeProviders(overrides = {}) {
  return REQUIRED_NOTIFICATION_CHANNELS.map((channel) => ({
    ...baseProvider(channel, 'prod'),
    ...overrides[channel],
  }));
}

function completeEvidence(overrides = {}) {
  return {
    release_id: 'rel_notif_provider_20260702',
    tenant_scope: 'tenant_staging_01',
    providers: completeProviders(overrides.providersByChannel ?? {}),
    soc_signoff: {
      owner: 'soc-lead',
      signed_at: '2026-07-02T12:00:00.000Z',
      reference: 'ticket://soc/notif-config/2026-07-02',
    },
    security_signoff: {
      owner: 'security-lead',
      signed_at: '2026-07-02T12:30:00.000Z',
      reference: 'ticket://security/notif-config/2026-07-02',
    },
    ...overrides,
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('notification provider config evidence CLI', () => {
  it('parses CLI arguments', () => {
    assert.deepEqual(parseArgs(['--input', 'evidence.json']), {
      input: 'evidence.json',
      out: 'output/notification-provider-config-evidence.json',
      validateOnly: false,
      help: false,
    });
    assert.throws(() => parseArgs([]), /--input is required/);
  });

  it('accepts complete metadata-only provider configuration evidence', () => {
    const evidence = completeEvidence();
    const validation = validateNotificationProviderConfigEvidence(evidence);
    assert.equal(validation.ok, true);
    assert.deepEqual(validation.coverage_gaps, []);

    const manifest = createNotificationProviderConfigManifest({
      createdAt: '2026-07-02T00:00:00.000Z',
      evidence,
    });
    assert.equal(manifest.artifact_type, 'notification_provider_config_evidence');
    assert.equal(manifest.providers.length, REQUIRED_NOTIFICATION_CHANNELS.length);
    assert.deepEqual(manifest.coverage_gaps, []);
    assert.equal(manifest.signoff.soc.owner, 'soc-lead');
  });

  it('reports missing channel coverage gaps', () => {
    const evidence = completeEvidence({
      providers: [
        baseProvider('webhook', 'only'),
        baseProvider('email', 'only'),
        baseProvider('slack', 'only'),
      ],
    });
    const validation = validateNotificationProviderConfigEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.deepEqual(validation.coverage_gaps, ['missing_channel:teams']);
    assert.throws(
      () => createNotificationProviderConfigManifest({ evidence }),
      /coverage gap\(s\): missing_channel:teams/,
    );
  });

  it('rejects nested metadata access_token and omits secrets from manifest', () => {
    const evidence = completeEvidence();
    evidence.providers[3] = {
      ...evidence.providers[3],
      metadata: { access_token: 'plain-secret-token' },
    };
    const validation = validateNotificationProviderConfigEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.ok(
      validation.forbidden_fields.some((field) => field.includes('access_token')),
    );
    assert.throws(
      () => createNotificationProviderConfigManifest({ evidence }),
      /Forbidden content in evidence/,
    );
    const redactedBlob = JSON.stringify(redactObject(evidence, 0, { omitSensitiveKeys: true }));
    assert.equal(redactedBlob.includes('access_token'), false);
    assert.equal(redactedBlob.includes('plain-secret-token'), false);
  });

  it('rejects plaintext provider credentials', () => {
    const evidence = completeEvidence({
      providersByChannel: {
        webhook: {
          encrypted_credential_ref_id: 'whsec_live_plaintext_not_allowed',
        },
      },
    });
    const validation = validateNotificationProviderConfigEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.match(
      validation.invalid_fields.map((entry) => entry.reason).join(','),
      /plaintext_credential_not_allowed/,
    );
    assert.throws(
      () => createNotificationProviderConfigManifest({ evidence }),
      /invalid field\(s\): providers\[0\]\.encrypted_credential_ref_id/,
    );
  });

  it('rejects webhook URLs with embedded credentials', () => {
    const evidence = completeEvidence({
      providersByChannel: {
        slack: {
          encrypted_credential_ref_id: 'secret://vault/notif/slack-prod',
        },
      },
      notes: 'https://user:pass@hooks.example.com/services/T000/B000/ZZZZ',
    });
    const validation = validateNotificationProviderConfigEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.match(validation.forbidden_fields.join(','), /notes:url_credentials/);
    assert.throws(
      () => createNotificationProviderConfigManifest({ evidence }),
      /Forbidden content in evidence/,
    );
  });

  it('validate-only does not write output', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'summary.json');
    writeJson(input, completeEvidence());
    const code = await main(['--input', input, '--out', out, '--validate-only']);
    assert.equal(code, 0);
    assert.equal(existsSync(out), false);
  });

  it('rejects token patterns in release_id before writing manifest', () => {
    const evidence = completeEvidence({
      release_id: 'rel_with svc_v1.fake.fake.fake token',
    });
    const validation = validateNotificationProviderConfigEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.ok(validation.forbidden_fields.some((field) => field.includes('token_pattern')));
    assert.throws(
      () => createNotificationProviderConfigManifest({ evidence }),
      /Forbidden content in evidence/,
    );
  });

  it('writes redacted summary output from JSON input', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'summary.json');
    writeJson(input, completeEvidence());
    const code = await main(['--input', input, '--out', out]);
    assert.equal(code, 0);
    const summary = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(summary.validation.ok, true);
    assert.equal(summary.release_id, 'rel_notif_provider_20260702');
    const blob = JSON.stringify(summary);
    assert.equal(blob.includes('svc_v1.fake.fake.fake'), false);
    assert.equal(blob.includes('webhook_url'), false);
    assert.deepEqual(summary.coverage_gaps, []);
  });
});