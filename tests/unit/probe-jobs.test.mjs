import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { getCheckById } from '../../src/contracts/checks.mjs';
import {
  buildSignedProbeJobRecord,
  resolveJobProbeProfile,
  targetDescriptor,
} from '../../src/lib/probeJobs.mjs';

const SECRET = 'a'.repeat(32);

describe('probeJobs capability profile plumbing', () => {
  it('resolveJobProbeProfile merges direct_ip and protected_host overrides', () => {
    const check = getCheckById('origin.host_sni_bypass.safe');
    const profile = resolveJobProbeProfile(check, {
      direct_ip: '198.51.100.7',
      protected_host: 'edge.example.test',
    });
    assert.equal(profile.kind, 'host_sni_bypass');
    assert.equal(profile.direct_ip, '198.51.100.7');
    assert.equal(profile.protected_host, 'edge.example.test');
  });

  it('targetDescriptor passes direct_origin_ip in job metadata', () => {
    const descriptor = targetDescriptor({
      id: 'tgt_1',
      kind: 'fqdn',
      value: 'edge.example.test',
      metadata: { direct_origin_ip: '198.51.100.7' },
    });
    assert.equal(descriptor.metadata.direct_origin_ip, '198.51.100.7');
  });

  it('buildSignedProbeJobRecord enriches host_sni_bypass from target metadata', () => {
    const check = getCheckById('origin.host_sni_bypass.safe');
    const job = buildSignedProbeJobRecord({
      run: { id: 'run_1', tenant_id: 'ten_1', safety_constraints: { max_requests: 1 } },
      check,
      target: {
        id: 'tgt_1',
        kind: 'fqdn',
        value: 'edge.example.test',
        metadata: {
          direct_origin_ip: '198.51.100.7',
          protected_host: 'edge.example.test',
        },
      },
      probeProfile: undefined,
      probeWorkerSecret: SECRET,
      now: new Date('2026-07-06T00:00:00.000Z'),
      newId: () => 'pjob_test',
    });
    assert.equal(job.probe_profile.direct_ip, '198.51.100.7');
    assert.equal(job.probe_profile.protected_host, 'edge.example.test');
    assert.equal(job.target.metadata.direct_origin_ip, '198.51.100.7');
  });

  it('buildSignedProbeJobRecord enriches direct reachability from target metadata', () => {
    const check = getCheckById('origin.direct_reachability.safe');
    const job = buildSignedProbeJobRecord({
      run: { id: 'run_1', tenant_id: 'ten_1', safety_constraints: { max_requests: 1 } },
      check,
      target: {
        id: 'tgt_1',
        kind: 'fqdn',
        value: 'edge.example.test',
        metadata: {
          direct_origin_ip: '198.51.100.8',
          protected_host: 'edge.example.test',
        },
      },
      probeProfile: undefined,
      probeWorkerSecret: SECRET,
      now: new Date('2026-07-06T00:00:00.000Z'),
      newId: () => 'pjob_direct',
    });
    assert.equal(job.probe_profile.kind, 'host_sni_bypass');
    assert.equal(job.probe_profile.direct_ip, '198.51.100.8');
    assert.equal(job.probe_profile.protected_host, 'edge.example.test');
    assert.equal(job.target.metadata.direct_origin_ip, '198.51.100.8');
  });
});
