import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { collectForbiddenEvidenceFields } from '../../src/lib/redact.mjs';
import {
  executeRemediationDelivery,
  extractRemediationOutboundBody,
  normalizeRemediationDeliverChannel,
  parseRemediationDeliveryModes,
  remediationDestinationPreview,
  resolveRemediationConnectorType,
  resolveRemediationDeliveryMode,
  resolveRemediationDestination,
} from '../../src/lib/remediationDelivery.mjs';
import { buildRemediationPayload, deliverActionItem, listActionItems } from '../../src/services/wafPosture.mjs';
import { createActionItem } from '../../src/contracts/wafPosture.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';

const forbiddenExtra = new Set(['raw_payload', 'credentials', 'tokens', 'secrets', 'api_key']);

function assertNoForbiddenFields(value, label) {
  const findings = collectForbiddenEvidenceFields(value, '', { extraForbiddenKeys: forbiddenExtra });
  assert.deepEqual(findings, [], `${label} must not include forbidden fields, found: ${findings.join(', ')}`);
}

const sampleActionItem = createActionItem({
  action_item_id: 'ai_delivery_1',
  category: 'waf_drift',
  title: 'WAF drift on app.example.com',
  asset: { id: 'asset_1', display: 'app.example.com', owner_hint: 'edge-team' },
  owner: 'edge-team',
  severity: 'high',
  evidence: {
    summary: 'Marker validation failed after protected baseline.',
    links: [{ type: 'finding', url: '/v1/findings/fnd_1', label: 'Finding' }],
  },
  recommended_solution: 'Restore blocking mode for managed rules.',
  retest_url: '/v1/waf/validations?waf_asset_id=asset_1',
  status: 'open',
  finding_ids: ['fnd_1'],
  tenant_id: 'ten_demo',
});

const samplePayload = buildRemediationPayload(sampleActionItem, 'jira');

const ctx = {
  tenantId: 'ten_demo',
  userId: 'usr_demo',
  role: 'engineer',
};

describe('remediation delivery adapters', () => {
  const envSnapshot = { ...process.env };

  afterEach(() => {
    process.env = { ...envSnapshot };
    delete process.env.ASTRANULL_REMEDIATION_DELIVERY_MODE;
    delete process.env.ASTRANULL_REMEDIATION_JIRA_URL;
    delete process.env.ASTRANULL_REMEDIATION_SERVICENOW_URL;
    delete process.env.ASTRANULL_REMEDIATION_SLACK_URL;
    delete process.env.ASTRANULL_REMEDIATION_WEBHOOK_URL;
    delete process.env.ASTRANULL_REMEDIATION_SIEM_URL;
    delete process.env.ASTRANULL_REMEDIATION_SIEM_PROVIDER;
  });

  it('parses remediation delivery modes for channels, all, and metadata_only', () => {
    const webhook = parseRemediationDeliveryModes('webhook,jira');
    assert.equal(webhook.has('webhook'), true);
    assert.equal(webhook.has('jira'), true);
    assert.equal(webhook.has('metadata_only'), false);

    const all = parseRemediationDeliveryModes('all');
    assert.equal(all.has('jira'), true);
    assert.equal(all.has('siem'), true);

    const metadataOnly = parseRemediationDeliveryModes('metadata_only');
    assert.deepEqual([...metadataOnly], ['metadata_only']);
    assert.equal(resolveRemediationDeliveryMode({}), 'metadata_only');
    assert.equal(resolveRemediationDeliveryMode({ deliveryMode: 'webhook,slack' }), 'slack,webhook');
  });

  it('normalizes deliverable channels and SIEM connector aliases', () => {
    assert.equal(normalizeRemediationDeliverChannel('Jira'), 'jira');
    assert.equal(normalizeRemediationDeliverChannel('splunk_hec'), 'siem');
    assert.equal(normalizeRemediationDeliverChannel('sentinel'), 'siem');
    assert.equal(normalizeRemediationDeliverChannel('email'), null);
    assert.equal(resolveRemediationConnectorType('siem'), 'splunk_hec');
    process.env.ASTRANULL_REMEDIATION_SIEM_PROVIDER = 'sentinel';
    assert.equal(resolveRemediationConnectorType('siem'), 'sentinel');
  });

  it('extracts connector-specific outbound bodies without secrets', () => {
    const splunkPayload = buildRemediationPayload(sampleActionItem, 'splunk_hec');
    const splunkBody = extractRemediationOutboundBody('splunk_hec', splunkPayload);
    assert.ok(splunkBody.event);
    assert.equal(splunkBody.event.schema_version, 'astranull.waf_event.v1');
    assertNoForbiddenFields(splunkBody, 'splunk outbound body');

    const slackPayload = buildRemediationPayload(sampleActionItem, 'slack');
    const slackBody = extractRemediationOutboundBody('slack', slackPayload);
    assert.ok(Array.isArray(slackBody.blocks));
    assert.match(String(slackBody.text), /high/);
    assertNoForbiddenFields(slackBody, 'slack outbound body');
  });

  it('dry_run returns metadata_only preview without network I/O', async () => {
    const result = await executeRemediationDelivery({
      channel: 'jira',
      connectorType: 'jira',
      payload: samplePayload,
      dryRun: true,
    });

    assert.equal(result.status, 'metadata_only');
    assert.equal(result.reason, 'dry_run_payload_preview');
    assert.equal(result.dry_run, true);
    assert.ok(result.payload);
    assert.equal(result.payload.connector, 'jira');
    assertNoForbiddenFields(result, 'dry_run delivery result');
  });

  it('rejects outbound delivery when mode is metadata_only', async () => {
    process.env.ASTRANULL_REMEDIATION_JIRA_URL = 'https://jira.example.invalid/rest/api/2/issue';
    const result = await executeRemediationDelivery({
      channel: 'jira',
      connectorType: 'jira',
      payload: samplePayload,
      dryRun: false,
      destination: process.env.ASTRANULL_REMEDIATION_JIRA_URL,
    });

    assert.equal(result.status, 'queued_provider_not_configured');
    assert.equal(result.reason, 'remediation_delivery_mode_metadata_only');
    assert.equal(result.dry_run, false);
  });

  it('rejects non-HTTPS destinations and URL-embedded credentials', async () => {
    process.env.ASTRANULL_REMEDIATION_DELIVERY_MODE = 'webhook';

    const httpResult = await executeRemediationDelivery({
      channel: 'webhook',
      connectorType: 'webhook',
      payload: buildRemediationPayload(sampleActionItem, 'webhook'),
      dryRun: false,
      destination: 'http://public.example.com/hook',
    });
    assert.equal(httpResult.status, 'provider_failed_dlq');
    assert.equal(httpResult.reason, 'invalid_webhook_destination');

    const credResult = await executeRemediationDelivery({
      channel: 'webhook',
      connectorType: 'webhook',
      payload: buildRemediationPayload(sampleActionItem, 'webhook'),
      dryRun: false,
      destination: 'https://user:pass@hooks.example.invalid/waf',
    });
    assert.equal(credResult.status, 'provider_failed_dlq');
    assert.equal(credResult.reason, 'webhook_url_credentials_not_allowed');
  });

  it('delivers when mode and destination are configured', async () => {
    process.env.ASTRANULL_REMEDIATION_DELIVERY_MODE = 'slack';
    const destination = 'https://hooks.slack.invalid/services/test';
    let called = false;

    const result = await executeRemediationDelivery({
      channel: 'slack',
      connectorType: 'slack',
      payload: buildRemediationPayload(sampleActionItem, 'slack'),
      dryRun: false,
      destination,
      fetchFn: async (url, init) => {
        called = true;
        assert.equal(url, destination);
        assert.equal(init.method, 'POST');
        assert.equal(init.redirect, 'manual');
        const body = JSON.parse(init.body);
        assert.ok(Array.isArray(body.blocks));
        assertNoForbiddenFields(body, 'slack POST body');
        return { ok: true, status: 200 };
      },
    });

    assert.equal(called, true);
    assert.equal(result.status, 'delivered_provider');
    assert.equal(result.reason, 'slack_delivered');
    assert.equal(result.attempt_number, 1);
    assert.equal(result.max_attempts, 3);
    assert.match(result.destination_preview ?? '', /slack:\/\/hooks\.slack\.invalid/);
  });

  it('retries retryable provider failures with bounded attempts', async () => {
    process.env.ASTRANULL_REMEDIATION_DELIVERY_MODE = 'webhook';
    const destination = 'https://hooks.example.invalid/waf';
    let calls = 0;
    const backoffDelays = [];

    const result = await executeRemediationDelivery({
      channel: 'webhook',
      connectorType: 'webhook',
      payload: buildRemediationPayload(sampleActionItem, 'webhook'),
      dryRun: false,
      destination,
      baseBackoffMs: 10,
      sleepFn: async (ms) => {
        backoffDelays.push(ms);
      },
      fetchFn: async () => {
        calls += 1;
        if (calls < 3) {
          return { ok: false, status: 503 };
        }
        return { ok: true, status: 200 };
      },
    });

    assert.equal(calls, 3);
    assert.deepEqual(backoffDelays, [10, 20]);
    assert.equal(result.status, 'delivered_provider');
    assert.equal(result.reason, 'webhook_delivered');
    assert.equal(result.attempt_number, 3);
    assert.equal(result.max_attempts, 3);
    assert.equal(result.exhausted, false);
  });

  it('returns provider_failed_dlq after exhausting retryable failures', async () => {
    process.env.ASTRANULL_REMEDIATION_DELIVERY_MODE = 'jira';
    const destination = 'https://jira.example.invalid/rest/api/2/issue';
    let calls = 0;

    const result = await executeRemediationDelivery({
      channel: 'jira',
      connectorType: 'jira',
      payload: samplePayload,
      dryRun: false,
      destination,
      baseBackoffMs: 1,
      sleepFn: async () => {},
      fetchFn: async () => {
        calls += 1;
        return { ok: false, status: 503 };
      },
    });

    assert.equal(calls, 3);
    assert.equal(result.status, 'provider_failed_dlq');
    assert.equal(result.reason, 'provider_http_error');
    assert.equal(result.attempt_number, 3);
    assert.equal(result.max_attempts, 3);
    assert.equal(result.exhausted, true);
    assert.equal(result.provider_error, 'provider_http_error');
  });

  it('does not retry non-retryable provider failures', async () => {
    process.env.ASTRANULL_REMEDIATION_DELIVERY_MODE = 'webhook';
    const destination = 'https://hooks.example.invalid/waf';
    let calls = 0;

    const result = await executeRemediationDelivery({
      channel: 'webhook',
      connectorType: 'webhook',
      payload: buildRemediationPayload(sampleActionItem, 'webhook'),
      dryRun: false,
      destination,
      fetchFn: async () => {
        calls += 1;
        return { ok: false, status: 400 };
      },
    });

    assert.equal(calls, 1);
    assert.equal(result.status, 'provider_failed_dlq');
    assert.equal(result.reason, 'provider_http_error');
    assert.equal(result.attempt_number, 1);
    assert.equal(result.max_attempts, 3);
    assert.equal(result.exhausted, true);
  });

  it('remediationDestinationPreview redacts host and path hints only', () => {
    const preview = remediationDestinationPreview(
      'jira',
      'https://jira.example.invalid/rest/api/2/issue?token=secret',
    );
    assert.match(preview, /^jira:\/\/jira\.example\.invalid/);
    assert.equal(preview.includes('secret'), false);
  });

  it('resolveRemediationDestination reads per-channel env vars', () => {
    process.env.ASTRANULL_REMEDIATION_WEBHOOK_URL = 'https://hooks.example.invalid/waf';
    assert.equal(resolveRemediationDestination('webhook'), process.env.ASTRANULL_REMEDIATION_WEBHOOK_URL);
  });
});

describe('deliverActionItem service', () => {
  afterEach(() => {
    freshStore();
  });

  it('returns dry_run delivery preview for a tenant action item', async () => {
    freshStore();
    listActionItems(ctx);
    getStore().wafActionItems.push({
      ...sampleActionItem,
      tenant_id: 'ten_demo',
      dedupe_key: 'asset_1:marker_rule_not_blocking',
      created_at: '2026-07-02T00:00:00.000Z',
      updated_at: '2026-07-02T00:00:00.000Z',
    });

    const result = await deliverActionItem(ctx, 'ai_delivery_1', 'jira', { dry_run: true });
    assert.equal(result.delivery.action_item_id, 'ai_delivery_1');
    assert.equal(result.delivery.channel, 'jira');
    assert.equal(result.delivery.status, 'metadata_only');
    assert.equal(result.delivery.dry_run, true);
    assert.ok(result.delivery.payload);

    const audits = getStore().auditLog.filter((e) => e.action === 'waf.action_item.delivered');
    assert.equal(audits.length, 1);
    assert.equal(audits[0].metadata.channel, 'jira');
    assert.equal(audits[0].metadata.dry_run, true);
    assert.equal(JSON.stringify(audits[0]).includes('hooks'), false);
  });

  it('returns 404 for missing action items and 400 for invalid channels', async () => {
    freshStore();
    const missing = await deliverActionItem(ctx, 'missing', 'jira', { dry_run: true });
    assert.equal(missing.error, 'waf_action_item_not_found');
    assert.equal(missing.status, 404);

    listActionItems(ctx);
    getStore().wafActionItems.push({
      ...sampleActionItem,
      tenant_id: 'ten_demo',
      dedupe_key: 'asset_1:marker_rule_not_blocking',
      created_at: '2026-07-02T00:00:00.000Z',
      updated_at: '2026-07-02T00:00:00.000Z',
    });

    const invalid = await deliverActionItem(ctx, 'ai_delivery_1', 'email', { dry_run: true });
    assert.equal(invalid.error, 'invalid_request');
    assert.equal(invalid.status, 400);
  });
});