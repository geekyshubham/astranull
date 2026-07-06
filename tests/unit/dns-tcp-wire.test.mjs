import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  accumulateDnsTcpResponse,
  buildAxfrDnsMessage,
  encodeDnsQName,
  frameDnsTcpMessage,
  parseDnsResponseHeader,
} from '../../src/lib/dnsTcpWire.mjs';

function refusedDnsMessage(rcode = 5) {
  const dns = Buffer.alloc(12);
  dns[3] = rcode;
  return dns;
}

describe('dnsTcpWire', () => {
  const cases = [
    {
      name: 'framed REFUSED strips TCP prefix',
      build: () => frameDnsTcpMessage(refusedDnsMessage(5)),
      options: { transport: 'tcp' },
      expect: { rcode: 5, answer_count: 0, incomplete: false, tcp_framed: true },
    },
    {
      name: 'partial TCP chunk is incomplete',
      build: () => frameDnsTcpMessage(refusedDnsMessage(5)).subarray(0, 6),
      options: { transport: 'tcp' },
      expect: { rcode: null, incomplete: true, tcp_framed: true },
    },
    {
      name: 'raw UDP DNS does not strip txid bytes as TCP length',
      build: () => {
        const dns = refusedDnsMessage(5);
        dns.writeUInt16BE(0xabcd, 0);
        return dns;
      },
      options: { transport: 'udp' },
      expect: { rcode: 5, answer_count: 0, incomplete: false, tcp_framed: false },
    },
    {
      name: 'two TCP chunks accumulate to complete frame',
      build: () => {
        const framed = frameDnsTcpMessage(refusedDnsMessage(5));
        return Buffer.concat([framed.subarray(0, 4), framed.subarray(4)]);
      },
      options: { transport: 'tcp' },
      expect: { rcode: 5, answer_count: 0, incomplete: false, tcp_framed: true },
    },
  ];

  for (const { name, build, options, expect } of cases) {
    it(name, () => {
      const parsed = parseDnsResponseHeader(build(), options);
      if ('rcode' in expect) assert.equal(parsed.rcode, expect.rcode);
      if ('answer_count' in expect) assert.equal(parsed.answer_count, expect.answer_count);
      if ('incomplete' in expect) assert.equal(parsed.incomplete, expect.incomplete);
      if ('tcp_framed' in expect) assert.equal(parsed.tcp_framed, expect.tcp_framed);
    });
  }

  it('buildAxfrDnsMessage encodes QNAME and AXFR QTYPE', () => {
    const qname = encodeDnsQName('example.test');
    assert.equal(qname.length, 14);
    const message = buildAxfrDnsMessage('example.test');
    assert.equal(message.readUInt16BE(qname.length + 12), 252);
    assert.equal(message.readUInt16BE(qname.length + 14), 1);
  });

  it('frameDnsTcpMessage prefixes RFC 1035 TCP length', () => {
    const message = buildAxfrDnsMessage('example.test');
    const framed = frameDnsTcpMessage(message);
    assert.equal(framed.readUInt16BE(0), message.length);
    assert.deepEqual(framed.subarray(2), message);
  });

  it('accumulateDnsTcpResponse completes only after split chunks arrive', () => {
    const framed = frameDnsTcpMessage(refusedDnsMessage(5));
    const first = accumulateDnsTcpResponse(Buffer.alloc(0), framed.subarray(0, 4));
    assert.equal(first.complete, false);
    assert.equal(first.parsed.incomplete, true);

    const second = accumulateDnsTcpResponse(first.buffer, framed.subarray(4));
    assert.equal(second.complete, true);
    assert.equal(second.parsed.rcode, 5);
    assert.equal(second.parsed.answer_count, 0);
  });
});