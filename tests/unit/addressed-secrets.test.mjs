import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  createAddressedSecret,
  parseAddressedSecret,
} from '../../src/lib/addressedSecrets.mjs';

describe('addressed secrets', () => {
  it('creates and parses bootstrap addressed secrets', () => {
    const secret = createAddressedSecret('ast_', 'ten_demo', 'token_abc');
    assert.ok(secret.startsWith('ast_v1.'));
    const parsed = parseAddressedSecret(secret, 'ast_');
    assert.deepEqual(parsed, { tenantId: 'ten_demo', id: 'token_abc', version: 'v1' });
  });

  it('creates and parses service-account addressed secrets', () => {
    const secret = createAddressedSecret('svc_', 'ten_other', 'sacc_deadbeef');
    assert.ok(secret.startsWith('svc_v1.'));
    const parsed = parseAddressedSecret(secret, 'svc_');
    assert.deepEqual(parsed, { tenantId: 'ten_other', id: 'sacc_deadbeef', version: 'v1' });
  });

  it('creates and parses agent addressed secrets', () => {
    const secret = createAddressedSecret('agc_', 'ten_demo', 'agent_abc');
    assert.ok(secret.startsWith('agc_v1.'));
    const parsed = parseAddressedSecret(secret, 'agc_');
    assert.deepEqual(parsed, { tenantId: 'ten_demo', id: 'agent_abc', version: 'v1' });
  });

  it('returns null for legacy opaque tokens', () => {
    assert.equal(parseAddressedSecret('ast_legacyopaquebase64material', 'ast_'), null);
    assert.equal(parseAddressedSecret('svc_legacyopaquebase64material', 'svc_'), null);
    assert.equal(parseAddressedSecret('agc_legacyopaquebase64material', 'agc_'), null);
  });

  it('rejects wrong prefix, extra parts, and malformed segments', () => {
    const valid = createAddressedSecret('ast_', 'ten_demo', 'token_1');
    assert.equal(parseAddressedSecret(valid, 'svc_'), null);
    assert.equal(parseAddressedSecret(`${valid}.extra`, 'ast_'), null);
    assert.equal(parseAddressedSecret('ast_v1..idB64.random', 'ast_'), null);
    assert.equal(parseAddressedSecret('ast_v1.%%%!.idB64.random', 'ast_'), null);

    const agcValid = createAddressedSecret('agc_', 'ten_demo', 'agent_1');
    assert.equal(parseAddressedSecret(agcValid, 'ast_'), null);
    assert.equal(parseAddressedSecret('agc_v1..idB64.random', 'agc_'), null);
    assert.equal(parseAddressedSecret('agc_v1.%%%!.idB64.random', 'agc_'), null);
  });

  it('still parses valid addressed secrets after strict segment validation', () => {
    const ast = createAddressedSecret('ast_', 'ten_strict', 'token_strict');
    const svc = createAddressedSecret('svc_', 'ten_svc', 'sacc_strict');
    assert.deepEqual(parseAddressedSecret(ast, 'ast_'), {
      tenantId: 'ten_strict',
      id: 'token_strict',
      version: 'v1',
    });
    assert.deepEqual(parseAddressedSecret(svc, 'svc_'), {
      tenantId: 'ten_svc',
      id: 'sacc_strict',
      version: 'v1',
    });
  });

  it('rejects tenant segment with invalid base64url characters', () => {
    const valid = createAddressedSecret('ast_', 'ten_demo', 'token_1');
    const [, , idB64, random] = valid.split('.');
    assert.equal(parseAddressedSecret(`ast_v1.ten%demo.${idB64}.${random}`, 'ast_'), null);
  });

  it('rejects id segment that is not canonical UTF-8 base64url', () => {
    const valid = createAddressedSecret('ast_', 'ten_demo', 'token_1');
    const [, tenantB64, , random] = valid.split('.');
    assert.equal(parseAddressedSecret(`ast_v1.${tenantB64}.idB64.${random}`, 'ast_'), null);
  });

  it('rejects random segment with invalid base64url characters', () => {
    const valid = createAddressedSecret('ast_', 'ten_demo', 'token_1');
    const [, tenantB64, idB64] = valid.split('.');
    assert.equal(parseAddressedSecret(`ast_v1.${tenantB64}.${idB64}.bad!random`, 'ast_'), null);
  });

  it('rejects padded base64url segments', () => {
    const valid = createAddressedSecret('ast_', 'ten_demo', 'token_1');
    const [, tenantB64, idB64, random] = valid.split('.');
    assert.equal(parseAddressedSecret(`ast_v1.${tenantB64}=.${idB64}.${random}`, 'ast_'), null);
    assert.equal(parseAddressedSecret(`ast_v1.${tenantB64}.${idB64}.${random}=`, 'ast_'), null);
  });

  it('rejects wrong number of dot-separated parts', () => {
    const valid = createAddressedSecret('ast_', 'ten_demo', 'token_1');
    assert.equal(parseAddressedSecret('ast_v1.onlythree.parts', 'ast_'), null);
    assert.equal(parseAddressedSecret(`${valid}.fifth`, 'ast_'), null);
  });
});