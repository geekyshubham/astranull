import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  assertNoRawWafEvidence,
  classifyWafPosture,
  CONTROL_BYPASS_CLASSES,
  deriveControlBypassStatus,
  mapReasonCodesToControlBypassClasses,
  normalizeScenarioIntakeInput,
  normalizeWafAssetInput,
  normalizeWafEvidenceSummary,
  normalizeWafValidationRequest,
} from '../../src/contracts/wafPosture.mjs';
import { migrateDevStore, resetStoreForTests } from '../../src/store.mjs';

describe('WAF posture contract', () => {
  it('rejects forbidden raw evidence keys at any depth', () => {
    assert.throws(
      () => assertNoRawWafEvidence({ summary: { raw_payload: 'x' } }),
      /Forbidden raw WAF evidence/,
    );
    assert.throws(
      () => assertNoRawWafEvidence({ nested: { headers: { host: 'example' } } }),
      /Forbidden raw WAF evidence/,
    );
    assert.throws(
      () => normalizeWafEvidenceSummary({ request_id: 'req_1', exploit_payload: 'no' }),
      /Forbidden raw WAF evidence/,
    );
  });

  it('normalizes metadata-only evidence summaries', () => {
    const summary = normalizeWafEvidenceSummary({
      request_id: 'req_1',
      blocked: true,
      response_code_class: '4xx',
    });
    assert.deepEqual(summary, {
      request_id: 'req_1',
      blocked: true,
      response_code_class: '4xx',
    });
    assert.throws(
      () => normalizeWafEvidenceSummary({ request_id: 'req_1', notes: 'free text' }),
      /Disallowed WAF evidence summary field/,
    );
  });

  it('normalizes declared WAF assets without discovery auto-approval', () => {
    const asset = normalizeWafAssetInput({
      target_group_id: 'tg_1',
      hostname: 'app.example.com',
      expected_waf_required: '0',
    });
    assert.equal(asset.canonical_url, 'app.example.com');
    assert.equal(asset.expected_waf_required, false);
    assert.equal(asset.status, 'unknown');

    assert.throws(
      () => normalizeWafAssetInput({
        target_group_id: 'tg_1',
        canonical_url: 'https://app.example.com',
        auto_approve: true,
      }),
      /Automatic discovery approval/,
    );
  });

  it('caps and rejects unsafe WAF validation profiles', () => {
    const safe = normalizeWafValidationRequest({
      waf_asset_id: 'waf_1',
      modes: ['marker'],
      probe_profile: { max_requests: 5, timeout_ms: 5000 },
      marker_profile: { marker_type: 'header', expected_action: 'block' },
      risk_class: 'controlled',
    });
    assert.equal(safe.probe_profile.max_requests, 5);
    assert.equal(safe.probe_profile.timeout_ms, 5000);

    const rateLimit = normalizeWafValidationRequest({
      waf_asset_id: 'waf_1',
      modes: ['rate_limit_safe'],
      marker_profile: { marker_type: 'header', expected_action: 'rate_limit' },
    });
    assert.equal(rateLimit.marker_profile.expected_action, 'rate_limit');

    assert.throws(
      () => normalizeWafValidationRequest({
        waf_asset_id: 'waf_1',
        modes: ['marker'],
        probe_profile: { max_requests: 10 },
      }),
      /max_requests must be an integer between 1 and 5/,
    );
    assert.throws(
      () => normalizeWafValidationRequest({
        waf_asset_id: 'waf_1',
        modes: ['marker'],
        probe_profile: { timeout_ms: 50 },
      }),
      /timeout_ms must be an integer between 100 and 5000/,
    );
    assert.throws(
      () => normalizeWafValidationRequest({
        waf_asset_id: 'waf_1',
        modes: ['marker'],
        risk_class: 'soc_gated',
      }),
      /risk_class must be safe or controlled/,
    );
    assert.throws(
      () => normalizeWafValidationRequest({
        waf_asset_id: 'waf_1',
        modes: ['marker'],
        prohibited: true,
      }),
      /prohibited is not permitted/,
    );
    assert.throws(
      () => normalizeWafValidationRequest({
        waf_asset_id: 'waf_1',
        modes: ['marker'],
        raw_payload: 'attack',
      }),
      /Forbidden raw WAF evidence/,
    );
  });

  it('classifyWafPosture does not claim protected without validation pass', () => {
    const detectedOnly = classifyWafPosture({
      wafDetected: true,
      validationPassed: false,
      wafRequired: true,
    });
    assert.equal(detectedOnly.status, 'unknown');
    assert.ok(detectedOnly.reason_codes.includes('insufficient_validation_evidence'));

    const protectedPosture = classifyWafPosture({
      wafDetected: true,
      validationPassed: true,
      wafRequired: true,
    });
    assert.equal(protectedPosture.status, 'protected');

    const failed = classifyWafPosture({
      wafDetected: true,
      validationFailed: true,
      validationPassed: false,
    });
    assert.equal(failed.status, 'underprotected');
    assert.ok(failed.reason_codes.includes('marker_rule_not_blocking'));
  });

  it('maps reason codes to control-bypass taxonomy classes', () => {
    assert.equal(CONTROL_BYPASS_CLASSES.length, 6);
    const classes = mapReasonCodesToControlBypassClasses(['origin_bypass_confirmed']);
    assert.equal(classes.length, 2);
    assert.ok(classes.some((entry) => entry.id === 'direct_origin_reachability'));
    assert.equal(deriveControlBypassStatus({ reason_codes: ['origin_bypass_confirmed'] }), 'confirmed');
    assert.equal(deriveControlBypassStatus({ reason_codes: ['marker_rule_not_blocking'] }), 'suspected');
    assert.equal(deriveControlBypassStatus({ reason_codes: [] }), 'none');
  });

  it('normalizes metadata-only scenario intake without exploit fields', () => {
    const intake = normalizeScenarioIntakeInput({
      pattern_title: 'HTTP/2 parser normalization edge',
      advisory_refs: ['CVE-2026-12345', 'advisory:cloudflare-2026-01'],
      proposed_scenario_family: 'http2_parser_marker',
      risk_class: 'metadata_only',
      threat_summary: 'Metadata-only parser class reference.',
    });
    assert.equal(intake.pattern_title, 'HTTP/2 parser normalization edge');
    assert.equal(intake.proposed_scenario_family, 'http2_parser_marker');
    assert.throws(
      () => normalizeScenarioIntakeInput({
        pattern_title: 'bad',
        advisory_refs: ['CVE-2026-12345'],
        exploit_payload: 'no',
      }),
      /Forbidden (scenario intake field|raw WAF evidence)/,
    );
  });

  it('migrateDevStore adds WAF collections idempotently', () => {
    process.env.ASTRANULL_NO_PERSIST = '1';
    const legacy = { tenants: [] };
    resetStoreForTests(legacy);
    assert.equal(migrateDevStore(legacy), true);
    assert.deepEqual(legacy.wafAssets, []);
    assert.deepEqual(legacy.wafScenarioIntakes, []);
    assert.deepEqual(legacy.wafProducts, []);
    assert.deepEqual(legacy.externalAssetCandidates, []);
    assert.deepEqual(legacy.wafRuleRecommendations, []);
    assert.equal(migrateDevStore(legacy), false);
  });
});
