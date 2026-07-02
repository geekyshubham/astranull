import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, it, beforeEach, afterEach } from 'node:test';
import {
  EXPOSURE_TYPES,
  RISK_STATES,
  createSupplyChainRisk,
  validateRiskItem,
  scoreRiskSeverity,
  canTransitionRiskState,
} from '../../src/contracts/supplyChainRisk.mjs';
import {
  assessDanglingCname,
  assessDanglingDependency,
  createRemediationTicket,
  createSupplyChainRisk as createSupplyChainRiskService,
  listSupplyChainRisks,
  patchRiskState,
} from '../../src/services/supplyChainRisk.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const adminCtx = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };

const ORIGINAL_WAF_FLAG = process.env.ASTRANULL_WAF_POSTURE_ENABLED;

function enableWafFeature() {
  process.env.ASTRANULL_WAF_POSTURE_ENABLED = '1';
}

function disableWafFeature() {
  delete process.env.ASTRANULL_WAF_POSTURE_ENABLED;
}

function baseRiskFields(overrides = {}) {
  return {
    risk_id: 'risk_test_1',
    exposure_type: 'dangling_cname',
    hostname: 'stale.app.example.com',
    evidence_summary: {
      cname_chain_hash: 'abc123',
      provider_error_signature_id: 'azure_app_deleted_v1',
      confidence: 0.8,
    },
    confidence: 0.8,
    severity: 'medium',
    state: 'suspected',
    owner_hint: 'platform-team',
    remediation_steps: ['Remove dangling CNAME.'],
    ...overrides,
  };
}

describe('supply chain risk contract', () => {
  it('creates risk items with required fields and valid exposure types', () => {
    const item = createSupplyChainRisk(baseRiskFields());
    assert.equal(item.risk_id, 'risk_test_1');
    assert.equal(item.exposure_type, 'dangling_cname');
    assert.equal(item.hostname, 'stale.app.example.com');
    assert.ok(item.evidence_summary.cname_chain_hash);
    assert.equal(item.owner_hint, 'platform-team');
    assert.deepEqual(item.remediation_steps, ['Remove dangling CNAME.']);

    assert.throws(
      () => createSupplyChainRisk(baseRiskFields({ exposure_type: 'invalid_type' })),
      /exposure_type must be one of/,
    );
    assert.throws(
      () => createSupplyChainRisk(baseRiskFields({ hostname: '' })),
      /hostname is required/,
    );
    assert.throws(
      () => createSupplyChainRisk(baseRiskFields({ confidence: 1.5 })),
      /confidence must be a number between 0 and 1/,
    );

    for (const exposureType of EXPOSURE_TYPES) {
      const created = createSupplyChainRisk(baseRiskFields({ exposure_type: exposureType }));
      assert.equal(created.exposure_type, exposureType);
    }
  });

  it('rejects forbidden raw and exploit fields', () => {
    for (const forbiddenField of [
      'exploit_code',
      'page_body',
      'html_source',
      'raw_response',
      'cookies',
      'credentials',
      'tokens',
      'secrets',
      'dns_zone_file',
      'private_key',
    ]) {
      assert.throws(
        () => validateRiskItem({ [forbiddenField]: 'unsafe' }),
        /Forbidden supply chain risk field/,
      );
      assert.throws(
        () => createSupplyChainRisk(baseRiskFields({ [forbiddenField]: 'unsafe' })),
        /Forbidden supply chain risk field/,
      );
    }
  });

  it('scores severity for claimable signatures and critical page types', () => {
    const claimable = scoreRiskSeverity(baseRiskFields({
      severity: 'low',
      evidence_summary: {
        claimable_provider_signature: true,
        provider_error_signature_id: 'heroku_app_missing',
      },
    }));
    assert.equal(claimable.severity, 'critical');
    assert.equal(claimable.state, 'confirmed');

    const paymentPage = scoreRiskSeverity(baseRiskFields({
      severity: 'low',
      evidence_summary: {
        page_type: 'payment',
        connector_confirmation: true,
      },
    }));
    assert.equal(paymentPage.severity, 'critical');

    const noProof = scoreRiskSeverity(baseRiskFields({
      evidence_summary: { cname_chain_hash: 'only_hash' },
      confidence: 0.9,
      state: 'confirmed',
    }));
    assert.equal(noProof.state, 'suspected');

    const subsidiary = scoreRiskSeverity(baseRiskFields({
      evidence_summary: {
        provider_error_signature_id: 'sig',
        subsidiary_acquisition: true,
      },
      confidence: 0.9,
    }));
    assert.ok(subsidiary.confidence <= 0.65);

    const connectorBoost = scoreRiskSeverity(baseRiskFields({
      evidence_summary: { connector_confirms_missing: true },
      confidence: 0.55,
    }));
    assert.ok(connectorBoost.confidence >= 0.75);
  });

  it('allows only valid state transitions', () => {
    assert.equal(canTransitionRiskState('suspected', 'confirmed'), true);
    assert.equal(canTransitionRiskState('confirmed', 'remediation_pending'), true);
    assert.equal(canTransitionRiskState('remediation_pending', 'resolved'), true);
    assert.equal(canTransitionRiskState('resolved', 'suspected'), false);
    assert.equal(canTransitionRiskState('accepted_risk', 'confirmed'), false);
    assert.equal(canTransitionRiskState('suspected', 'suspected'), true);
  });
});

describe('supply chain risk service', () => {
  beforeEach(() => {
    freshStore();
    enableWafFeature();
  });

  afterEach(() => {
    if (ORIGINAL_WAF_FLAG === undefined) {
      delete process.env.ASTRANULL_WAF_POSTURE_ENABLED;
    } else {
      process.env.ASTRANULL_WAF_POSTURE_ENABLED = ORIGINAL_WAF_FLAG;
    }
  });

  it('lists tenant-scoped risks and deduplicates by hostname and exposure_type', () => {
    const first = createSupplyChainRiskService(adminCtx, baseRiskFields());
    assert.equal(first.deduplicated, false);
    const second = createSupplyChainRiskService(adminCtx, baseRiskFields({ risk_id: 'risk_test_2' }));
    assert.equal(second.deduplicated, true);
    assert.equal(second.risk.id, first.risk.id);

    const listed = listSupplyChainRisks(adminCtx);
    assert.equal(listed.length, 1);
    assert.equal(listed[0].hostname, 'stale.app.example.com');
  });

  it('assesses dangling CNAME from metadata without DNS lookups', () => {
    const result = assessDanglingCname(adminCtx, {
      hostname: 'orphan.example.com',
      cname_chain_hash: 'chain_hash_1',
      provider_error_signature_id: 's3_bucket_missing',
      connector_confirmation: true,
    });
    assert.equal(result.assessed, true);
    assert.equal(result.created, true);
    assert.equal(result.risk.exposure_type, 'dangling_cname');
    assert.equal(result.risk.state, 'confirmed');
    assert.equal(getStore().supplyChainRisks.length, 1);

    const lowConfidence = assessDanglingCname(adminCtx, {
      hostname: 'weak.example.com',
      cname_chain_hash: 'chain_only',
    });
    assert.equal(lowConfidence.created, false);
    assert.equal(lowConfidence.reason, 'below_confidence_threshold');
  });

  it('assesses dangling dependency from metadata without scraping', () => {
    const result = assessDanglingDependency(adminCtx, {
      hostname: 'checkout.example.com',
      script_host: 'cdn.vendor.example',
      dependency_url_hash: 'dep_hash_1',
      status_code: 404,
      content_type: 'text/html',
      page_type: 'payment',
    });
    assert.equal(result.assessed, true);
    assert.equal(result.created, true);
    assert.equal(result.risk.exposure_type, 'dangling_script_inclusion');
    assert.equal(result.risk.severity, 'critical');
    assert.equal(result.risk.evidence_summary.script_host, 'cdn.vendor.example');
    assert.equal(getStore().supplyChainRisks.length, 1);
  });

  it('creates redacted remediation tickets without secrets', () => {
    const created = createSupplyChainRiskService(adminCtx, baseRiskFields());
    const ticketResult = createRemediationTicket(adminCtx, created.risk.id, {
      owner_hint: 'secops@example.com',
    });
    const { ticket } = ticketResult;
    assert.equal(ticket.hostname, 'stale.app.example.com');
    assert.equal(ticket.severity, created.risk.severity);
    assert.ok(ticket.title.includes('dangling_cname'));
    assert.ok(ticket.retest_link.includes(created.risk.id));
    assert.equal(ticket.owner_hint, 'secops@example.com');
    assert.ok(ticket.evidence_summary.cname_chain_hash);
    assert.equal('secrets' in ticket, false);
    assert.equal('credentials' in ticket, false);

    const audit = getStore().auditLog.find((a) => a.action === 'supply_chain.ticket.created');
    assert.ok(audit);
  });

  it('patches risk state with audited transitions', () => {
    const created = createSupplyChainRiskService(adminCtx, baseRiskFields());
    const patched = patchRiskState(adminCtx, created.risk.id, 'confirmed');
    assert.equal(patched.risk.state, 'confirmed');

    const invalid = patchRiskState(adminCtx, created.risk.id, 'resolved');
    assert.equal(invalid.error, 'invalid_state_transition');

    const audit = getStore().auditLog.find((a) => a.action === 'supply_chain.risk.state_changed');
    assert.ok(audit);
  });

  it('returns waf_feature_disabled when feature flag is off', () => {
    disableWafFeature();
    const result = listSupplyChainRisks(adminCtx);
    assert.deepEqual(result, { error: 'waf_feature_disabled' });
    assert.deepEqual(createSupplyChainRiskService(adminCtx, baseRiskFields()), { error: 'waf_feature_disabled' });
    assert.deepEqual(assessDanglingCname(adminCtx, { hostname: 'x.example.com' }), { error: 'waf_feature_disabled' });
  });

  it('rejects prohibited acquisition fields and contains no acquisition code paths', () => {
    const blocked = createSupplyChainRiskService(adminCtx, {
      ...baseRiskFields(),
      claim_resource: true,
    });
    assert.equal(blocked.error, 'prohibited_acquisition');

    const contractSrc = readFileSync(
      path.join(process.cwd(), 'src/contracts/supplyChainRisk.mjs'),
      'utf8',
    );
    const serviceSrc = readFileSync(
      path.join(process.cwd(), 'src/services/supplyChainRisk.mjs'),
      'utf8',
    );
    const combined = `${contractSrc}\n${serviceSrc}`;
    const forbiddenPatterns = [
      /\bdns\.lookup\b/,
      /\bdns\.resolve\b/,
      /\bfetch\s*\(/,
      /\bhttp\.request\b/,
      /\bhttps\.request\b/,
      /\bclaimResource\b/i,
      /\bacquireResource\b/i,
      /\bcreateAccount\b/i,
      /\bmodifyDns\b/i,
    ];
    for (const pattern of forbiddenPatterns) {
      assert.equal(pattern.test(combined), false, `forbidden pattern found: ${pattern}`);
    }
    assert.ok(combined.includes('prohibited_acquisition'));
    assert.ok(combined.includes('AP0_detect_only'));
    assert.ok(!combined.includes('AP3_governed_active') || combined.includes('RISK_PHASES'));
  });
});