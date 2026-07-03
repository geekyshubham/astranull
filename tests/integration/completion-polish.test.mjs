import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { after, before, describe, it } from 'node:test';
import path from 'node:path';
import { createServer } from '../../src/server.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { verifyCustodyManifest } from '../../src/lib/custody.mjs';
import { getStore } from '../../src/store.mjs';
import { artifactProofBody, validHighScaleRequestPayload } from '../helpers/highScalePayload.mjs';

let baseUrl;
let server;

before(() => {
  freshStore();
  server = createServer();
  server.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

const SECRET_MARKERS = [/ast_[A-Za-z0-9_-]{8,}/, /agc_[A-Za-z0-9_-]{8,}/];

function assertNoSecrets(text) {
  for (const pattern of SECRET_MARKERS) {
    assert.doesNotMatch(text, pattern);
  }
}

describe('completion polish security and observability', () => {
  it('denies customer roles on /internal/soc/*', async () => {
    const hs = await request(baseUrl, 'POST', '/v1/high-scale-requests', {
      headers: demoHeaders('engineer'),
      body: validHighScaleRequestPayload({ objective: 'rbac' }),
    });
    const hsId = hs.json.id;
    const art = await request(baseUrl, 'POST', `/v1/high-scale-requests/${hsId}/artifacts`, {
      headers: demoHeaders('engineer'),
      body: artifactProofBody('test_plan'),
    });
    const artId = art.json.id;

    for (const role of ['owner', 'admin', 'engineer', 'viewer', 'auditor']) {
      const headers = demoHeaders(role, 'ten_demo', `usr_${role}`);
      for (const [label, path, method, body] of [
        ['approve', `/internal/soc/high-scale/${hsId}/approve`, 'POST', undefined],
        ['schedule', `/internal/soc/high-scale/${hsId}/schedule`, 'POST', { window_start: '2026-01-01T00:00:00.000Z', window_end: '2026-01-02T00:00:00.000Z' }],
        ['start', `/internal/soc/high-scale/${hsId}/start`, 'POST', undefined],
        ['stop', `/internal/soc/high-scale/${hsId}/stop`, 'POST', undefined],
        ['close', `/internal/soc/high-scale/${hsId}/close`, 'POST', undefined],
        ['artifact review', `/internal/soc/high-scale/${hsId}/artifacts/${artId}/review`, 'POST', { status: 'accepted' }],
        ['notes', `/internal/soc/high-scale/${hsId}/notes`, 'POST', { body: 'nope' }],
        ['adapter status', `/internal/soc/high-scale/${hsId}/adapter-status`, 'GET', undefined],
        ['kill switch', '/internal/soc/kill-switch', 'POST', { active: true }],
      ]) {
        const res = await request(baseUrl, method, path, { headers, body });
        assert.equal(res.status, 403, `role ${role} should not access ${label}`);
        assert.equal(res.json.error, 'forbidden');
      }
    }

    assert.ok(getStore().auditLog.some((a) => a.action === 'rbac.denied'));
  });

  it('rejects packet payload fields on event ingestion', async () => {
    const h = demoHeaders('engineer');
    const pkt = await request(baseUrl, 'POST', '/v1/events', {
      headers: h,
      body: { event_id: 'evt_pkt_1', packet_payload: 'deadbeef' },
    });
    assert.equal(pkt.status, 400);
    assert.equal(pkt.json.error, 'packet_payload_forbidden');

    const raw = await request(baseUrl, 'POST', '/v1/events', {
      headers: h,
      body: { event_id: 'evt_pkt_2', raw_packet: { bytes: '00' } },
    });
    assert.equal(raw.status, 400);
    assert.equal(raw.json.error, 'packet_payload_forbidden');

    const nested = await request(baseUrl, 'POST', '/v1/events', {
      headers: h,
      body: { event_id: 'evt_pkt_3', metadata: { sample: { headers: { authorization: 'secret' } } } },
    });
    assert.equal(nested.status, 400);
    assert.equal(nested.json.error, 'packet_payload_forbidden');

    const evidenceNested = await request(baseUrl, 'POST', '/v1/events', {
      headers: h,
      body: { event_id: 'evt_pkt_4', evidence: { metadata: { request: { body: 'raw' } } } },
    });
    assert.equal(evidenceNested.status, 400);
    assert.equal(evidenceNested.json.error, 'packet_payload_forbidden');

    const camelRawPacket = await request(baseUrl, 'POST', '/v1/events', {
      headers: h,
      body: { event_id: 'evt_pkt_5', metadata: { rawPacket: { bytes: '00' } } },
    });
    assert.equal(camelRawPacket.status, 400);
    assert.equal(camelRawPacket.json.error, 'packet_payload_forbidden');

    const camelRequestBody = await request(baseUrl, 'POST', '/v1/events', {
      headers: h,
      body: { event_id: 'evt_pkt_6', metadata: { requestBody: 'raw' } },
    });
    assert.equal(camelRequestBody.status, 400);
    assert.equal(camelRequestBody.json.error, 'packet_payload_forbidden');

    const compactRawPayload = await request(baseUrl, 'POST', '/v1/events', {
      headers: h,
      body: { event_id: 'evt_pkt_7', metadata: { rawpayload: 'deadbeef' } },
    });
    assert.equal(compactRawPayload.status, 400);
    assert.equal(compactRawPayload.json.error, 'packet_payload_forbidden');

    const compactRequestHeaders = await request(baseUrl, 'POST', '/v1/events', {
      headers: h,
      body: { event_id: 'evt_pkt_8', metadata: { requestheaders: { authorization: 'secret' } } },
    });
    assert.equal(compactRequestHeaders.status, 400);
    assert.equal(compactRequestHeaders.json.error, 'packet_payload_forbidden');

    const directAuthorization = await request(baseUrl, 'POST', '/v1/events', {
      headers: h,
      body: { event_id: 'evt_pkt_9', metadata: { authorization: 'Bearer secret' } },
    });
    assert.equal(directAuthorization.status, 400);
    assert.equal(directAuthorization.json.error, 'packet_payload_forbidden');

    const variantAuthorization = await request(baseUrl, 'POST', '/v1/events', {
      headers: h,
      body: { event_id: 'evt_pkt_10', evidence: { metadata: { 'authori-zation': 'Bearer secret' } } },
    });
    assert.equal(variantAuthorization.status, 400);
    assert.equal(variantAuthorization.json.error, 'packet_payload_forbidden');
  });

  it('serves /metrics and /v1/observability', async () => {
    const metrics = await request(baseUrl, 'GET', '/metrics');
    assert.equal(metrics.status, 200);
    assert.match(metrics.text, /http_requests_total/);

    const obs = await request(baseUrl, 'GET', '/v1/observability', { headers: demoHeaders('viewer') });
    assert.equal(obs.status, 200);
    assert.ok(typeof obs.json.counters === 'object' || obs.json.http_requests_total !== undefined);
  });

  it('report exports redact ast_ and agc_ secrets across json, markdown, and html', async () => {
    const h = demoHeaders('admin');
    const soc = demoHeaders('soc', 'ten_demo', 'usr_soc');
    const hs = await request(baseUrl, 'POST', '/v1/high-scale-requests', {
      headers: demoHeaders('engineer'),
      body: validHighScaleRequestPayload({ objective: 'redaction export' }),
    });
    await request(baseUrl, 'POST', `/internal/soc/high-scale/${hs.json.id}/notes`, {
      headers: soc,
      body: {
        body: 'seen agc_abc123456789012345678901234 and ast_leaktoken123456789012345678 in transcript',
      },
    });

    const created = await request(baseUrl, 'POST', '/v1/reports', {
      headers: h,
      body: { title: 'Redaction Test', kind: 'technical' },
    });
    const reportId = created.json.id;

    const jsonExp = await request(baseUrl, 'GET', `/v1/reports/${reportId}/export?format=json`, { headers: h });
    assert.equal(jsonExp.status, 200);
    assertNoSecrets(JSON.stringify(jsonExp.json));

    const mdExp = await request(baseUrl, 'GET', `/v1/reports/${reportId}/export?format=markdown`, { headers: h });
    assert.equal(mdExp.status, 200);
    assertNoSecrets(mdExp.text);

    const htmlExp = await request(baseUrl, 'GET', `/v1/reports/${reportId}/export?format=html`, { headers: h });
    assert.equal(htmlExp.status, 200);
    assert.match(htmlExp.text, /<html/i);
    assert.doesNotMatch(htmlExp.text, /<script/i);
    assertNoSecrets(htmlExp.text);

    assert.ok(jsonExp.json.custody);
    assert.equal(jsonExp.json.custody.artifact_type, 'report_export');
    assert.equal(verifyCustodyManifest({ payload: jsonExp.json.payload, custody: jsonExp.json.custody }).ok, true);

    assert.match(mdExp.text, /## Custody/);
    assert.match(mdExp.text, /content_sha256:/);

    assert.match(htmlExp.text, /<h2>Custody<\/h2>/);
    assert.match(htmlExp.text, /content_sha256:/);

    const exportAudits = getStore().auditLog.filter(
      (a) => a.action === 'report.exported' && a.resource_id === reportId,
    );
    assert.equal(exportAudits.length, 3);
    assert.deepEqual(
      exportAudits.map((a) => a.metadata.format).sort(),
      ['html', 'json', 'markdown'],
    );
    const allowedAuditMetadataKeys = ['content_sha256', 'custody_schema_version', 'format'];
    for (const entry of exportAudits) {
      assert.ok(entry.metadata.content_sha256);
      assert.equal(entry.metadata.custody_schema_version, 'astranull.custody.v1');
      assert.deepEqual(Object.keys(entry.metadata).sort(), allowedAuditMetadataKeys);
      const metaJson = JSON.stringify(entry.metadata);
      assert.equal(metaJson.includes('seen agc'), false);
      assert.equal(metaJson.includes('Redaction Test'), false);
      assert.equal(metaJson.includes(jsonExp.json.payload.title), false);
    }
    const jsonExportAudit = exportAudits.find((a) => a.metadata.format === 'json');
    assert.ok(jsonExportAudit);
    assert.equal(jsonExportAudit.prev_hash, jsonExp.json.custody.previous_audit_hash);
  });

  it('finding export includes verifiable custody and safe audit metadata', async () => {
    const h = demoHeaders('admin');
    const store = getStore();
    store.findings.push({
      id: 'fnd_custody_1',
      tenant_id: 'ten_demo',
      title: 'Custody finding',
      severity: 'medium',
      status: 'open',
      check_id: 'chk_http_reachability',
      evidence_ids: ['ev_custody_a', 'ev_custody_b'],
      notes: 'internal note with ast_shouldnotappearintoauditmetadata1234567890',
    });

    const exp = await request(baseUrl, 'POST', '/v1/findings/fnd_custody_1/export', { headers: h });
    assert.equal(exp.status, 200);
    assert.equal(exp.json.finding_id, 'fnd_custody_1');
    assert.ok(exp.json.custody);
    assert.equal(exp.json.custody.artifact_type, 'finding_export');
    assert.deepEqual(exp.json.custody.subject_ids, ['ev_custody_a', 'ev_custody_b', 'fnd_custody_1']);
    const { custody, ...payload } = exp.json;
    assert.equal(verifyCustodyManifest({ payload, custody }).ok, true);

    const auditEntry = getStore().auditLog.find(
      (a) => a.action === 'finding.exported' && a.resource_id === 'fnd_custody_1',
    );
    assert.ok(auditEntry);
    assert.ok(auditEntry.metadata.content_sha256);
    assert.equal(auditEntry.metadata.format, 'json');
    assert.equal(JSON.stringify(auditEntry.metadata).includes('internal note'), false);
    assert.equal(auditEntry.prev_hash, exp.json.custody.previous_audit_hash);
    assert.ok(exp.json.custody.previous_tenant_audit_hash == null || typeof exp.json.custody.previous_tenant_audit_hash === 'string');
  });

  it('safety-check scans implementation paths but skips its own file', () => {
    const root = path.join(process.cwd(), 'scripts', 'safety-check.mjs');
    const script = spawnSync(process.execPath, [root], { encoding: 'utf8' });
    assert.equal(script.status, 0, script.stderr || script.stdout);
    assert.match(script.stdout, /safety-check: ok/);
  });
});
