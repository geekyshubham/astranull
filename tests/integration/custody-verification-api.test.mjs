import assert from 'node:assert/strict';
import { after, afterEach, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

const envSnapshot = { ...process.env };

let baseUrl;
let server;

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

async function createJsonReportExport() {
  const headers = demoHeaders('admin', 'ten_demo', 'usr_admin');
  const created = await request(baseUrl, 'POST', '/v1/reports', {
    headers,
    body: { title: 'Custody Verify Secret ast_should_not_echo_12345678', kind: 'technical' },
  });
  assert.equal(created.status, 201);
  const exported = await request(baseUrl, 'GET', `/v1/reports/${created.json.id}/export?format=json`, {
    headers,
  });
  assert.equal(exported.status, 200);
  assert.ok(exported.json.payload);
  assert.ok(exported.json.custody);
  return exported.json;
}

before(() => {
  freshStore();
  process.env.ASTRANULL_NO_PERSIST = '1';
  server = createServer();
  server.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server?.close();
  restoreEnv();
});

afterEach(() => {
  freshStore();
  process.env.ASTRANULL_NO_PERSIST = '1';
});

describe('custody verification API', () => {
  it('verifies report export custody without echoing the payload', async () => {
    const exported = await createJsonReportExport();
    const res = await request(baseUrl, 'POST', '/v1/custody/verify', {
      headers: demoHeaders('auditor', 'ten_demo', 'usr_auditor'),
      body: { payload: exported.payload, custody: exported.custody },
    });

    assert.equal(res.status, 200);
    assert.equal(res.json.ok, true);
    assert.equal(res.json.verification.ok, true);
    assert.equal(res.json.verification.schema_version, 'astranull.custody.v1');
    assert.equal(res.json.verification.artifact_type, 'report_export');
    assert.equal(res.json.verification.artifact_id, exported.custody.artifact_id);
    assert.equal(res.json.verification.content_sha256, exported.custody.content_sha256);
    assert.equal(res.json.verification.content_canonicalization, 'json-key-sorted-v1');
    assert.ok(res.json.verification.verified_at);

    const responseText = JSON.stringify(res.json);
    assert.equal(responseText.includes(exported.payload.title), false);
    assert.equal(responseText.includes('ast_should_not_echo_12345678'), false);
    assert.equal('payload' in res.json, false);
  });

  it('returns a mismatch result for tampered payloads', async () => {
    const exported = await createJsonReportExport();
    const res = await request(baseUrl, 'POST', '/v1/custody/verify', {
      headers: demoHeaders('admin'),
      body: {
        payload: { ...exported.payload, title: 'tampered' },
        custody: exported.custody,
      },
    });

    assert.equal(res.status, 200);
    assert.equal(res.json.ok, false);
    assert.equal(res.json.verification.ok, false);
    assert.equal(res.json.verification.error, 'content_sha256_mismatch');
  });

  it('forbids non-audit roles', async () => {
    const exported = await createJsonReportExport();
    for (const role of ['viewer', 'engineer']) {
      const res = await request(baseUrl, 'POST', '/v1/custody/verify', {
        headers: demoHeaders(role),
        body: { payload: exported.payload, custody: exported.custody },
      });
      assert.equal(res.status, 403);
      assert.equal(res.json.permission, 'audit:read');
    }
  });

  it('audits safe verification metadata only', async () => {
    const exported = await createJsonReportExport();
    const before = getStore().auditLog.length;
    const res = await request(baseUrl, 'POST', '/v1/custody/verify', {
      headers: demoHeaders('soc', 'ten_demo', 'usr_soc'),
      body: { payload: exported.payload, custody: exported.custody },
    });
    assert.equal(res.status, 200);

    const entry = getStore().auditLog
      .slice(before)
      .find((item) => item.action === 'custody.verified');
    assert.ok(entry);
    assert.equal(entry.resource_type, 'custody_manifest');
    assert.equal(entry.resource_id, exported.custody.artifact_id);
    assert.deepEqual(Object.keys(entry.metadata).sort(), [
      'artifact_type',
      'content_sha256',
      'custody_schema_version',
      'ok',
    ]);
    assert.equal(entry.metadata.ok, true);
    const auditText = JSON.stringify(entry);
    assert.equal(auditText.includes(exported.payload.title), false);
    assert.equal(auditText.includes('ast_should_not_echo_12345678'), false);
  });

  it('returns custody_missing for missing manifests', async () => {
    const res = await request(baseUrl, 'POST', '/v1/custody/verify', {
      headers: demoHeaders('admin'),
      body: { payload: { report_id: 'rpt_missing' } },
    });

    assert.equal(res.status, 200);
    assert.equal(res.json.ok, false);
    assert.equal(res.json.verification.ok, false);
    assert.equal(res.json.verification.error, 'custody_missing');
    assert.equal('payload' in res.json, false);
  });
});
