import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import * as dnsOwnership from '../../src/services/dnsOwnership.mjs';
import { getStore } from '../../src/store.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { createDnsStub, resetDnsStub } from '../helpers/dns-stub.mjs';
import { freshStore } from '../helpers/reset.mjs';

let server;
let baseUrl;
let dnsStub;

before(() => {
  freshStore();
  resetDnsStub();
  dnsStub = createDnsStub();
  server = createServer({
    services: {
      dnsOwnership: {
        ...dnsOwnership,
        verifyDnsOwnership: (scope, body, opts = {}) =>
          dnsOwnership.verifyDnsOwnership(scope, body, { resolveTxt: dnsStub.resolveTxt, ...opts }),
      },
    },
  });
  server.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server?.close();
});

beforeEach(() => {
  freshStore();
  resetDnsStub();
});

describe('target lifecycle (FT-CRUD-TGT-01)', () => {
  it('create → DNS verify → dns_verified chip → delete excludes from LOA scope', async () => {
    const headers = demoHeaders('engineer');
    const group = await request(baseUrl, 'POST', '/v1/target-groups', {
      headers,
      body: { name: 'Target lifecycle', environment_id: 'env_demo' },
    });
    assert.equal(group.status, 201);
    const groupId = group.json.id;

    const created = await request(baseUrl, 'POST', `/v1/target-groups/${groupId}/targets`, {
      headers,
      body: { kind: 'fqdn', value: 'lifecycle.example.test' },
    });
    assert.equal(created.status, 201);
    const targetId = created.json.id;

    const issued = await request(baseUrl, 'POST', `/v1/target-groups/${groupId}/dns-ownership/issue`, {
      headers,
      body: { target_id: targetId },
    });
    assert.equal(issued.status, 201);
    const recordValue = issued.json.challenge.record_value;
    dnsStub.setTxt(issued.json.challenge.record_name, [recordValue]);

    const verified = await request(baseUrl, 'POST', `/v1/target-groups/${groupId}/dns-ownership/verify`, {
      headers,
      body: { target_id: targetId },
    });
    assert.equal(verified.status, 200);
    assert.equal(verified.json.verified, true);

    const detail = await request(baseUrl, 'GET', `/v1/targets/${targetId}`, { headers });
    assert.equal(detail.status, 200);
    assert.equal(detail.json.verification.state, 'dns_verified');

    const loaBefore = await request(baseUrl, 'POST', `/v1/target-groups/${groupId}/loa`, {
      headers,
      body: {
        signer_name: 'Lifecycle Signer',
        signer_title: 'Eng',
        signer_email: 'signer@lifecycle.example',
        attested: true,
        emergency_contact: { name: 'Ops', role: 'SRE', phone: '+1', email: 'ops@lifecycle.example' },
      },
    });
    assert.equal(loaBefore.status, 201);
    assert.ok(
      loaBefore.json.loa.scope_snapshot.excluded.some((row) => row.target_id === targetId),
    );

    const deleted = await request(baseUrl, 'DELETE', `/v1/target-groups/${groupId}/targets/${targetId}`, {
      headers,
    });
    assert.equal(deleted.status, 200);

    const targetsAfter = getStore().targets.filter(
      (row) => row.target_group_id === groupId && row.tenant_id === 'ten_demo',
    );
    assert.equal(targetsAfter.some((row) => row.id === targetId), false);

    const audits = getStore().auditLog
      .filter((entry) => entry.resource_id === targetId || entry.metadata?.target_group_id === groupId)
      .map((entry) => entry.action);
    assert.ok(audits.includes('target.added'));
    assert.ok(audits.includes('dns_ownership.challenge_issued'));
    assert.ok(audits.includes('target.deleted'));
  });
});