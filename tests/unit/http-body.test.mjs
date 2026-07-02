import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { describe, it } from 'node:test';
import { HttpBodyError, readJsonBody } from '../../src/lib/http.mjs';

function mockReq(chunks) {
  return Readable.from(chunks.map((c) => (typeof c === 'string' ? Buffer.from(c) : c)));
}

describe('readJsonBody', () => {
  it('returns {} for empty body', async () => {
    const body = await readJsonBody(mockReq([]), 1024);
    assert.deepEqual(body, {});
  });

  it('returns {} for whitespace-only body', async () => {
    const body = await readJsonBody(mockReq(['   \n']), 1024);
    assert.deepEqual(body, {});
  });

  it('parses valid JSON', async () => {
    const body = await readJsonBody(mockReq(['{"a":1}']), 1024);
    assert.deepEqual(body, { a: 1 });
  });

  it('throws invalid_json for malformed JSON', async () => {
    await assert.rejects(
      () => readJsonBody(mockReq(['{not-json']), 1024),
      (err) => {
        assert.ok(err instanceof HttpBodyError);
        assert.equal(err.code, 'invalid_json');
        assert.equal(err.status, 400);
        return true;
      },
    );
  });

  it('throws payload_too_large when body exceeds maxBytes', async () => {
    const big = 'x'.repeat(200);
    await assert.rejects(
      () => readJsonBody(mockReq([big]), 64),
      (err) => {
        assert.ok(err instanceof HttpBodyError);
        assert.equal(err.code, 'payload_too_large');
        assert.equal(err.status, 413);
        return true;
      },
    );
  });
});