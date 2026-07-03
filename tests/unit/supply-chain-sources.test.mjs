import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildSupplyChainSourceRef,
  isIpHostname,
  parseDanglingCnameSourceRecord,
  parseSupplyChainSourceRecord,
  parseSupplyChainSourceRecords,
  parseVendorDependencySourceRecord,
} from '../../src/lib/supplyChainSources.mjs';

describe('supply chain source parsers', () => {
  it('parses dangling_cname records into metadata-only assess fields', () => {
    const parsed = parseDanglingCnameSourceRecord({
      hostname: 'Stale.App.Example.COM',
      source_type: 'dangling_cname',
      cname_chain_hash: 'chain_hash_1',
      provider_error_signature_id: 'azure_app_deleted_v1',
      connector_confirmation: true,
      observed_at: '2026-07-03T10:00:00.000Z',
    });

    assert.equal(parsed.hostname, 'stale.app.example.com');
    assert.equal(parsed.source, 'dangling_cname');
    assert.equal(parsed.exposure_type, 'dangling_cname');
    assert.equal(parsed.confidence, 0.75);
    assert.equal(parsed.assess_body.hostname, 'stale.app.example.com');
    assert.equal(parsed.assess_body.cname_chain_hash, 'chain_hash_1');
    assert.equal(parsed.assess_body.provider_error_signature_id, 'azure_app_deleted_v1');
    assert.equal(parsed.assess_body.connector_confirmation, true);
    assert.ok(parsed.source_ref.startsWith('redacted:dangling_cname:'));
  });

  it('parses vendor_dependency records without raw URLs or page bodies', () => {
    const parsed = parseVendorDependencySourceRecord({
      hostname: 'checkout.example.com',
      source_type: 'vendor_dependency',
      script_host: 'cdn.vendor.example',
      dependency_url_hash: 'dep_hash_1',
      status_code: 404,
      connector_confirmation: true,
      observed_at: '2026-07-03T11:00:00.000Z',
    });

    assert.equal(parsed.hostname, 'checkout.example.com');
    assert.equal(parsed.source, 'vendor_dependency');
    assert.equal(parsed.exposure_type, 'vendor_dependency_risk');
    assert.equal(parsed.assess_body.script_host, 'cdn.vendor.example');
    assert.equal(parsed.assess_body.dependency_url_hash, 'dep_hash_1');
    assert.equal(parsed.assess_body.status_code, 404);
    assert.equal(parsed.assess_body.connector_confirmation, true);
    assert.ok(parsed.confidence >= 0.7);
  });

  it('rejects forbidden raw fields and IP hostnames', () => {
    assert.throws(
      () => parseDanglingCnameSourceRecord({
        hostname: 'orphan.example.com',
        source_type: 'dangling_cname',
        observed_at: '2026-07-03T10:00:00.000Z',
        dns_zone_file: 'zone data',
      }),
      /Forbidden supply chain source field/,
    );

    assert.throws(
      () => parseVendorDependencySourceRecord({
        hostname: 'checkout.example.com',
        source_type: 'vendor_dependency',
        observed_at: '2026-07-03T10:00:00.000Z',
        dependency_url: 'https://cdn.vendor.example/app.js',
      }),
      /Forbidden supply chain source field/,
    );

    assert.throws(
      () => parseDanglingCnameSourceRecord({
        hostname: '203.0.113.10',
        source_type: 'dangling_cname',
        observed_at: '2026-07-03T10:00:00.000Z',
      }),
      /must be a hostname, not an IP address/,
    );

    assert.equal(isIpHostname('203.0.113.10'), true);
    assert.equal(isIpHostname('app.example.com'), false);
  });

  it('requires matching batch source and validates record batches', () => {
    const parsed = parseSupplyChainSourceRecords('dangling_cname', [
      {
        hostname: 'a.example.com',
        source_type: 'dangling_cname',
        cname_chain_hash: 'hash_a',
        observed_at: '2026-07-03T10:00:00.000Z',
      },
      {
        hostname: 'b.example.com',
        source_type: 'dangling_cname',
        provider_error_signature_id: 'sig_b',
        confidence: 0.82,
        observed_at: '2026-07-03T11:00:00.000Z',
      },
    ]);
    assert.equal(parsed.length, 2);
    assert.equal(parsed[0].confidence, 0.4);
    assert.equal(parsed[1].confidence, 0.82);

    assert.throws(
      () => parseSupplyChainSourceRecords('dangling_cname', []),
      /at least one entry/,
    );
    assert.throws(
      () => parseSupplyChainSourceRecord('dangling_cname', {
        hostname: 'a.example.com',
        source_type: 'vendor_dependency',
        observed_at: '2026-07-03T10:00:00.000Z',
      }),
      /must match batch source/,
    );
    assert.throws(
      () => parseSupplyChainSourceRecord('invalid_source', {
        hostname: 'a.example.com',
        source_type: 'invalid_source',
        observed_at: '2026-07-03T10:00:00.000Z',
      }),
      /source must be one of/,
    );
  });

  it('builds stable redacted source references', () => {
    const first = buildSupplyChainSourceRef('vendor_dependency', 'app.example.com', '2026-07-03T10:00:00.000Z');
    const second = buildSupplyChainSourceRef('vendor_dependency', 'app.example.com', '2026-07-03T10:00:00.000Z');
    const different = buildSupplyChainSourceRef('vendor_dependency', 'app.example.com', '2026-07-03T11:00:00.000Z');
    assert.equal(first, second);
    assert.notEqual(first, different);
  });
});