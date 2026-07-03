import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildPassiveSourceRef,
  isIpHostname,
  mapPassiveSourceToCandidateSourceType,
  parsePassiveDiscoveryRecord,
  parsePassiveDiscoveryRecords,
} from '../../src/lib/discoverySources.mjs';

describe('discovery source parsers', () => {
  it('parses passive_dns records into metadata-only candidate fields', () => {
    const parsed = parsePassiveDiscoveryRecord('passive_dns', {
      hostname: 'Sub.Example.COM',
      source_type: 'passive_dns',
      confidence: 0.42,
      observed_at: '2026-07-03T10:00:00.000Z',
    });

    assert.equal(parsed.hostname, 'sub.example.com');
    assert.equal(parsed.source_type, 'passive_dns');
    assert.equal(parsed.passive_source, 'passive_dns');
    assert.equal(parsed.confidence, 0.42);
    assert.equal(parsed.approval_status, 'pending');
    assert.equal(parsed.state, 'candidate');
    assert.equal(parsed.evidence_summary.source_kind, 'passive_dns');
    assert.equal(parsed.evidence_summary.first_observed_at, '2026-07-03T10:00:00.000Z');
    assert.ok(parsed.source_ref.startsWith('redacted:passive_dns:'));
  });

  it('maps certificate_transparency to ct_log without retaining raw CT payloads', () => {
    const parsed = parsePassiveDiscoveryRecord('certificate_transparency', {
      hostname: 'api.example.com',
      source_type: 'certificate_transparency',
      confidence: 0.71,
      observed_at: '2026-07-03T11:00:00.000Z',
    });

    assert.equal(parsed.source_type, 'ct_log');
    assert.equal(parsed.passive_source, 'certificate_transparency');
    assert.equal(parsed.evidence_summary.cert_san_count, 1);
    assert.equal(
      mapPassiveSourceToCandidateSourceType('certificate_transparency'),
      'ct_log',
    );
  });

  it('rejects raw CT log fields and IP inventory hostnames', () => {
    assert.throws(
      () => parsePassiveDiscoveryRecord('certificate_transparency', {
        hostname: 'api.example.com',
        source_type: 'certificate_transparency',
        confidence: 0.5,
        observed_at: '2026-07-03T11:00:00.000Z',
        certificate: '-----BEGIN CERTIFICATE-----',
      }),
      /Forbidden passive source field/,
    );

    assert.throws(
      () => parsePassiveDiscoveryRecord('passive_dns', {
        hostname: '203.0.113.10',
        source_type: 'passive_dns',
        confidence: 0.5,
        observed_at: '2026-07-03T11:00:00.000Z',
      }),
      /must be a hostname, not an IP address/,
    );

    assert.equal(isIpHostname('203.0.113.10'), true);
    assert.equal(isIpHostname('api.example.com'), false);
  });

  it('requires matching batch source and validates record batches', () => {
    const parsed = parsePassiveDiscoveryRecords('passive_dns', [
      {
        hostname: 'a.example.com',
        source_type: 'passive_dns',
        observed_at: '2026-07-03T10:00:00.000Z',
      },
      {
        hostname: 'b.example.com',
        source_type: 'passive_dns',
        confidence: 0.55,
        observed_at: '2026-07-03T11:00:00.000Z',
      },
    ]);
    assert.equal(parsed.length, 2);
    assert.equal(parsed[0].confidence, 0.4);
    assert.equal(parsed[1].confidence, 0.55);

    assert.throws(
      () => parsePassiveDiscoveryRecords('passive_dns', []),
      /at least one entry/,
    );
    assert.throws(
      () => parsePassiveDiscoveryRecord('passive_dns', {
        hostname: 'a.example.com',
        source_type: 'certificate_transparency',
        confidence: 0.5,
        observed_at: '2026-07-03T10:00:00.000Z',
      }),
      /must match batch source/,
    );
  });

  it('builds stable redacted source references', () => {
    const first = buildPassiveSourceRef('passive_dns', 'app.example.com', '2026-07-03T10:00:00.000Z');
    const second = buildPassiveSourceRef('passive_dns', 'app.example.com', '2026-07-03T10:00:00.000Z');
    const different = buildPassiveSourceRef('passive_dns', 'app.example.com', '2026-07-03T11:00:00.000Z');
    assert.equal(first, second);
    assert.notEqual(first, different);
  });
});