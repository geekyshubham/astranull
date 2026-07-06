import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { executeCapabilityProbe } from '../../src/lib/capabilityProbes.mjs';
import { signProbeJob } from '../../src/lib/probeJobs.mjs';

const VERIFY_SECRET = 'c'.repeat(32);

function signedAxfrJob(zone) {
  const job = {
    id: 'pjob_live_axfr',
    tenant_id: 'ten_live',
    test_run_id: 'run_live',
    check_id: 'dns.zone_transfer_exposure.safe',
    nonce_hash: 'live_axfr_nonce_hash',
    constraints: { timeout_ms: 15000, max_requests: 1 },
    probe_profile: { kind: 'dns_axfr_leak', zone },
    target: { kind: 'fqdn', value: zone },
  };
  job.job_signature = signProbeJob(job, VERIFY_SECRET);
  return job;
}

describe('capability probes live public DNS (unaided I/O)', () => {
  it('dns_axfr_leak uses real resolveNs + net.connect against example.com NS', async () => {
    const outcome = await executeCapabilityProbe(
      signedAxfrJob('example.com'),
      { probeWorkerSecret: VERIFY_SECRET },
    );

    assert.equal(outcome.metadata.probe_kind, 'dns_axfr_leak');
    assert.equal(outcome.metadata.zone, 'example.com');
    assert.ok(outcome.metadata.nameserver, 'expected real nameserver hostname from public DNS');
    assert.equal(outcome.external_result, 'blocked');
    assert.equal(outcome.metadata.axfr_refused, true);
    assert.notEqual(outcome.metadata.axfr_leak, true);
    if (outcome.metadata.rcode === 0) {
      assert.equal(outcome.metadata.answer_count ?? 0, 0, 'NOERROR must have zero answers to avoid leak verdict');
    } else {
      assert.ok(outcome.metadata.rcode >= 1 && outcome.metadata.rcode <= 15, `unexpected DNS rcode ${outcome.metadata.rcode}`);
    }
    assert.equal(outcome.requests_sent, 1);
  });
});