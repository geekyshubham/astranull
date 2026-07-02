import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  EDGE_PROTECTION_CONTROL_IDS,
  EDGE_PROTECTION_EVIDENCE_FIELDS,
  EDGE_PROTECTION_REQUIRED_CONTROLS,
  listEdgeProtectionControls,
  validateEdgeProtectionEvidence,
} from '../../src/contracts/edgeProtectionBaseline.mjs';

function completeEvidence() {
  return {
    release_id: 'rel_2026_07_02',
    controls: EDGE_PROTECTION_REQUIRED_CONTROLS.map((control) => ({
      control_id: control.control_id,
      evidence_uri: `evidence://edge/${control.control_id}`,
      validated_at: '2026-07-02T00:00:00.000Z',
      owner: 'security-team',
      tls_policy: 'TLS 1.2+ with managed certificate rotation',
      allowed_hosts: ['app.astranull.example', 'api.astranull.example'],
      limit_summary: 'Gateway enforces bounded body, header count, and header size limits.',
      protection_summary: 'Credential-stuffing and bot protections enabled at the edge.',
      rule_family_summary: 'Managed API and application rule groups in block/challenge mode.',
      origin_exposure_summary: 'Origin accepts traffic only from the edge or private network.',
      log_destination: 'siem://edge-events',
      health_path_policy: '/health and /ready are allowlisted with narrow method and rate policy.',
      header_policy_summary: 'HSTS, frame, content-type, and referrer policies enabled.',
      spoofing_control_summary: 'Proxy strips inbound forwarding headers before adding trusted values.',
    })),
  };
}

describe('edge protection baseline contract', () => {
  it('lists every required edge protection control once', () => {
    assert.deepEqual(
      EDGE_PROTECTION_CONTROL_IDS,
      [
        'tls_termination',
        'host_allowlist',
        'request_size_limits',
        'bot_and_credential_stuffing_protection',
        'managed_waf_or_equivalent_rules',
        'origin_shielding',
        'edge_logging_and_audit',
        'health_endpoint_handling',
        'security_headers',
        'proxy_header_spoofing_controls',
      ],
    );
    assert.equal(new Set(EDGE_PROTECTION_CONTROL_IDS).size, EDGE_PROTECTION_CONTROL_IDS.length);
    assert.equal(listEdgeProtectionControls(), EDGE_PROTECTION_REQUIRED_CONTROLS);
  });

  it('exposes required evidence fields for each control', () => {
    for (const controlId of EDGE_PROTECTION_CONTROL_IDS) {
      assert.ok(EDGE_PROTECTION_EVIDENCE_FIELDS[controlId].includes('evidence_uri'));
      assert.ok(EDGE_PROTECTION_EVIDENCE_FIELDS[controlId].includes('validated_at'));
      assert.ok(EDGE_PROTECTION_EVIDENCE_FIELDS[controlId].includes('owner'));
    }
  });

  it('accepts complete metadata-only edge evidence', () => {
    assert.deepEqual(validateEdgeProtectionEvidence(completeEvidence()), {
      ok: true,
      missing_controls: [],
      invalid_controls: [],
      missing_fields: [],
      forbidden_fields: [],
    });
  });

  it('reports missing controls', () => {
    const evidence = completeEvidence();
    evidence.controls = evidence.controls.filter(
      (control) => control.control_id !== 'origin_shielding',
    );
    const result = validateEdgeProtectionEvidence(evidence);
    assert.equal(result.ok, false);
    assert.deepEqual(result.missing_controls, ['origin_shielding']);
  });

  it('reports missing required metadata fields', () => {
    const evidence = completeEvidence();
    const waf = evidence.controls.find(
      (control) => control.control_id === 'managed_waf_or_equivalent_rules',
    );
    delete waf.rule_family_summary;
    const result = validateEdgeProtectionEvidence(evidence);
    assert.equal(result.ok, false);
    assert.deepEqual(result.missing_fields, [
      {
        control_id: 'managed_waf_or_equivalent_rules',
        fields: ['rule_family_summary'],
      },
    ]);
  });

  it('rejects unknown controls', () => {
    const evidence = completeEvidence();
    evidence.controls.push({
      control_id: 'provider_specific_magic',
      evidence_uri: 'evidence://edge/provider-specific-magic',
      validated_at: '2026-07-02T00:00:00.000Z',
      owner: 'security-team',
    });
    const result = validateEdgeProtectionEvidence(evidence);
    assert.equal(result.ok, false);
    assert.deepEqual(result.invalid_controls, [
      { control_id: 'provider_specific_magic', reason: 'unknown_control' },
    ]);
  });

  it('rejects raw or secret-bearing evidence fields while allowing summaries', () => {
    const evidence = completeEvidence();
    const securityHeaders = evidence.controls.find(
      (control) => control.control_id === 'security_headers',
    );
    securityHeaders.raw_headers = { authorization: 'Bearer should-not-appear' };
    evidence.controls[0].metadata = { raw_log_line: 'GET /private token=secret' };

    const result = validateEdgeProtectionEvidence(evidence);
    assert.equal(result.ok, false);
    assert.deepEqual(result.forbidden_fields.sort(), [
      'controls[0].metadata.raw_log_line',
      'controls[8].raw_headers',
      'controls[8].raw_headers.authorization',
    ]);
    assert.equal(result.missing_fields.length, 0);
  });
});
