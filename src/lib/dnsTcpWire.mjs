/**
 * RFC 1035 DNS message encoding and DNS-over-TCP framing helpers.
 * Transport is explicit — callers must pass { transport: 'tcp' } for AXFR/TCP paths.
 */

export function encodeDnsQName(zone) {
  const labels = String(zone).split('.').filter(Boolean);
  const parts = [];
  for (const label of labels) {
    parts.push(Buffer.from([label.length]));
    parts.push(Buffer.from(label, 'ascii'));
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

/** Build a single AXFR DNS query message (payload without TCP length prefix). */
export function buildAxfrDnsMessage(zone) {
  const qname = encodeDnsQName(zone);
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x1234, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  const question = Buffer.alloc(qname.length + 4);
  qname.copy(question, 0);
  question.writeUInt16BE(252, qname.length);
  question.writeUInt16BE(1, qname.length + 2);
  return Buffer.concat([header, question]);
}

/** RFC 1035 §4.2.2 — prepend 16-bit message length for DNS-over-TCP. */
export function frameDnsTcpMessage(message) {
  const framed = Buffer.alloc(2 + message.length);
  framed.writeUInt16BE(message.length, 0);
  message.copy(framed, 2);
  return framed;
}

/**
 * Parse DNS response header from a buffer.
 * @param {Buffer} chunk
 * @param {{ transport?: 'tcp' | 'udp' }} [options] — use 'tcp' for DNS-over-TCP (AXFR); default 'udp' treats buffer as raw DNS.
 */
export function parseDnsResponseHeader(chunk, options = {}) {
  const transport = options.transport ?? 'udp';
  const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk ?? []);

  if (transport === 'tcp') {
    if (buffer.length < 2) {
      return {
        rcode: null,
        answer_count: 0,
        dns_message: buffer,
        incomplete: true,
        tcp_framed: true,
      };
    }
    const declaredLen = buffer.readUInt16BE(0);
    if (declaredLen < 12) {
      return {
        rcode: null,
        answer_count: 0,
        dns_message: buffer,
        incomplete: true,
        tcp_framed: true,
      };
    }
    if (buffer.length < declaredLen + 2) {
      return {
        rcode: null,
        answer_count: 0,
        dns_message: buffer,
        incomplete: true,
        tcp_framed: true,
      };
    }
    const dnsMessage = buffer.subarray(2, 2 + declaredLen);
    if (dnsMessage.length < 12) {
      return {
        rcode: null,
        answer_count: 0,
        dns_message: dnsMessage,
        incomplete: true,
        tcp_framed: true,
      };
    }
    return {
      rcode: dnsMessage[3] & 0x0f,
      answer_count: dnsMessage.readUInt16BE(6),
      dns_message: dnsMessage,
      incomplete: false,
      tcp_framed: true,
    };
  }

  if (buffer.length < 12) {
    return {
      rcode: null,
      answer_count: 0,
      dns_message: buffer,
      incomplete: true,
      tcp_framed: false,
    };
  }
  return {
    rcode: buffer[3] & 0x0f,
    answer_count: buffer.readUInt16BE(6),
    dns_message: buffer,
    incomplete: false,
    tcp_framed: false,
  };
}