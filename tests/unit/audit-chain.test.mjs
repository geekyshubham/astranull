import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  audit,
  buildAuditRecord,
  computeEntryHash,
  getLatestChainedAuditEntry,
  verifyAuditChain,
} from '../../src/audit.mjs';
import { buildCustodyManifest } from '../../src/lib/custody.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';

describe('tamper-evident audit chain', () => {
  it('buildAuditRecord redacts, sequences, chains, and verifies', () => {
    const fixedNow = new Date('2026-07-01T12:00:00.000Z');
    const prior = {
      id: 'evt_prior',
      timestamp: '2026-07-01T11:00:00.000Z',
      tenant_id: 'ten_a',
      sequence: 4,
      prev_hash: null,
      action: 'prior',
      resource_type: 'r',
      resource_id: 'p1',
    };
    prior.entry_hash = computeEntryHash(prior);
    const built = buildAuditRecord(
      {
        tenant_id: 'ten_a',
        actor_user_id: 'u1',
        actor_role: 'admin',
        action: 'token.used',
        resource_type: 'token',
        resource_id: 't1',
        metadata: { api_key: 'ast_supersecret1234567890' },
      },
      prior,
      fixedNow,
    );
    assert.equal(built.timestamp, fixedNow.toISOString());
    assert.equal(built.sequence, 5);
    assert.equal(built.prev_hash, prior.entry_hash);
    assert.ok(built.id.startsWith('evt_'));
    assert.equal(built.metadata.api_key, '[REDACTED]');
    assert.equal(built.entry_hash, computeEntryHash(built));
    assert.equal(verifyAuditChain([prior, built]).valid, true);

    const first = buildAuditRecord(
      {
        tenant_id: 'ten_a',
        action: 'first',
        resource_type: 'r',
        resource_id: '1',
      },
      null,
      fixedNow,
    );
    assert.equal(first.sequence, 1);
    assert.equal(first.prev_hash, null);
    assert.equal(verifyAuditChain([first]).valid, true);
  });

  it('appends sequence, prev_hash, and entry_hash', () => {
    freshStore();
    const first = audit({
      tenant_id: 'ten_a',
      actor_user_id: 'u1',
      actor_role: 'admin',
      action: 'test.action',
      resource_type: 'test',
      resource_id: 'x1',
    });
    assert.equal(first.sequence, 1);
    assert.equal(first.prev_hash, null);
    assert.ok(first.entry_hash);

    const second = audit({
      tenant_id: 'ten_a',
      actor_user_id: 'u1',
      actor_role: 'admin',
      action: 'test.action2',
      resource_type: 'test',
      resource_id: 'x2',
    });
    assert.equal(second.sequence, 2);
    assert.equal(second.prev_hash, first.entry_hash);

    const result = verifyAuditChain(getStore().auditLog);
    assert.equal(result.valid, true);
  });

  it('redacts secrets in metadata before storing', () => {
    freshStore();
    const record = audit({
      tenant_id: 'ten_a',
      actor_user_id: 'u1',
      actor_role: 'admin',
      action: 'token.used',
      resource_type: 'token',
      resource_id: 't1',
      metadata: { api_key: 'ast_supersecret1234567890' },
    });
    assert.equal(record.metadata.api_key, '[REDACTED]');
    assert.equal(verifyAuditChain(getStore().auditLog).valid, true);
  });

  it('fails verification when a chained entry is tampered', () => {
    freshStore();
    audit({
      tenant_id: 'ten_a',
      actor_user_id: 'u1',
      actor_role: 'admin',
      action: 'a',
      resource_type: 'r',
      resource_id: '1',
    });
    audit({
      tenant_id: 'ten_a',
      actor_user_id: 'u1',
      actor_role: 'admin',
      action: 'b',
      resource_type: 'r',
      resource_id: '2',
    });
    const log = getStore().auditLog;
    log[1].action = 'tampered';
    const result = verifyAuditChain(log);
    assert.equal(result.valid, false);
    assert.equal(result.error, 'entry_hash_mismatch');
    assert.equal(result.index, 1);
  });

  it('keeps entry_hash stable after JSON round-trip when optional fields are undefined', () => {
    freshStore();
    audit({
      tenant_id: 'ten_a',
      actor_user_id: 'u1',
      actor_role: 'admin',
      action: 'json.roundtrip',
      resource_type: 'test',
      resource_id: 'r1',
      metadata: { present: 'yes' },
    });
    const log = getStore().auditLog;
    log[0].metadata = { ...log[0].metadata, omitted_after_json: undefined };
    log[0].tags = [1, undefined, 3];
    log[0].entry_hash = computeEntryHash(log[0]);
    const roundTripped = JSON.parse(JSON.stringify(log));
    const result = verifyAuditChain(roundTripped);
    assert.equal(result.valid, true);
  });

  it('rejects non-monotonic sequence numbers on chained entries', () => {
    freshStore();
    audit({
      tenant_id: 'ten_a',
      actor_user_id: 'u1',
      actor_role: 'admin',
      action: 'a',
      resource_type: 'r',
      resource_id: '1',
    });
    audit({
      tenant_id: 'ten_a',
      actor_user_id: 'u1',
      actor_role: 'admin',
      action: 'b',
      resource_type: 'r',
      resource_id: '2',
    });
    const log = getStore().auditLog;
    log[1].sequence = 1;
    log[1].entry_hash = computeEntryHash(log[1]);
    const result = verifyAuditChain(log);
    assert.equal(result.valid, false);
    assert.equal(result.error, 'sequence_not_monotonic');
    assert.equal(result.index, 1);
  });

  it('getLatestChainedAuditEntry returns the hash the next audit() will chain from', () => {
    freshStore();
    audit({
      tenant_id: 'ten_a',
      actor_user_id: 'u1',
      actor_role: 'admin',
      action: 'a',
      resource_type: 'r',
      resource_id: '1',
    });
    const second = audit({
      tenant_id: 'ten_b',
      actor_user_id: 'u2',
      actor_role: 'admin',
      action: 'b',
      resource_type: 'r',
      resource_id: '2',
    });
    assert.equal(getLatestChainedAuditEntry()?.entry_hash, second.entry_hash);

    const custody = buildCustodyManifest({
      tenant_id: 'ten_demo',
      artifact_type: 'report_export',
      artifact_id: 'rpt_1',
      format: 'json',
      created_by: 'usr_1',
      content: { title: 'T' },
      previous_audit_hash: getLatestChainedAuditEntry()?.entry_hash ?? null,
    });
    const exportAudit = audit({
      tenant_id: 'ten_demo',
      actor_user_id: 'usr_1',
      actor_role: 'admin',
      action: 'report.exported',
      resource_type: 'report',
      resource_id: 'rpt_1',
      metadata: {
        format: custody.format,
        content_sha256: custody.content_sha256,
        custody_schema_version: custody.schema_version,
      },
    });
    assert.equal(custody.previous_audit_hash, second.entry_hash);
    assert.equal(exportAudit.prev_hash, custody.previous_audit_hash);
    assert.equal(exportAudit.prev_hash, second.entry_hash);
  });

  it('accepts legacy entries without chain fields alongside new chained entries', () => {
    freshStore();
    getStore().auditLog.push({
      id: 'event_legacy',
      timestamp: '2020-01-01T00:00:00.000Z',
      tenant_id: 'ten_a',
      action: 'legacy.event',
    });
    audit({
      tenant_id: 'ten_a',
      actor_user_id: 'u1',
      actor_role: 'admin',
      action: 'new.event',
      resource_type: 'r',
      resource_id: '1',
    });
    const log = getStore().auditLog;
    assert.equal(log[1].sequence, 1);
    assert.equal(verifyAuditChain(log).valid, true);
  });
});