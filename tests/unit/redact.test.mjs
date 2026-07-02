import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { redactObject, redactString } from '../../src/lib/redact.mjs';

describe('redaction', () => {
  it('redacts token patterns and sensitive keys', () => {
    const out = redactObject({
      authorization: 'Bearer ast_secret123456789012345678901234',
      note: 'token ast_abcdefghijklmnopqrstuvwx',
      nested: { api_key: 'sk-1234567890123456' },
    });
    assert.equal(out.authorization, '[REDACTED]');
    assert.match(out.note, /\[REDACTED\]/);
    assert.equal(out.nested.api_key, '[REDACTED]');
    assert.match(redactString('agc_abc123456789012345678901234'), /\[REDACTED\]/);
    const astAddressed = 'ast_v1.dGVuX2RlbW8.tokenXyZ.randomMaterialHere123';
    assert.equal(redactString(`prefix ${astAddressed} suffix`), 'prefix [REDACTED] suffix');
    const svcAddressed = 'svc_v1.dGVuX2RlbW8.sacc_abcd.randomMaterialHere456';
    assert.equal(redactString(`Bearer ${svcAddressed}`), 'Bearer [REDACTED]');
    const agcAddressed = 'agc_v1.dGVuX2RlbW8.YWdlbnRfMQ.randomMaterialHere789';
    assert.equal(redactString(`log ${agcAddressed} end`), 'log [REDACTED] end');
    assert.doesNotMatch(redactString(agcAddressed), /agc_v1\./);
  });
});