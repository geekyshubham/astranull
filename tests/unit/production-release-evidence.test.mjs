import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  PRODUCTION_RELEASE_EVIDENCE_KINDS,
  PRODUCTION_RELEASE_EVIDENCE_REQUIREMENTS,
  validateProductionReleaseEvidence,
} from '../../src/contracts/productionReleaseEvidence.mjs';
import { PRODUCTION_RELEASE_EVIDENCE_COMPLETE as COMPLETE } from '../fixtures/productionReleaseEvidenceComplete.mjs';

describe('production release evidence contracts', () => {
  it('defines all production release evidence kinds', () => {
    assert.deepEqual(PRODUCTION_RELEASE_EVIDENCE_KINDS, [
      'third_party_security_review',
      'migration_apply',
      'operator_runbook_exercise',
      'oidc_prod_auth_preflight',
      'edge_protection',
      'agent_sbom_provenance',
      'agent_install_matrix',
      'agent_mtls_gateway',
      'agent_trust_key_ceremony',
      'governed_adapter',
      'provider_approval',
      'kill_switch_drill',
      'postgres_concurrency',
      'dr_restore',
      'ui_accessibility_matrix',
      'notification_provider_config',
      'probe_fleet_matrix',
      'vector_safety_policy',
      'secret_rotation_drill',
      'observability_slo',
      'support_readiness',
      'evidence_snapshot_manifest',
      'postgres_tenant_query_audit',
      'rollback_fixforward',
      'kms_vault_posture',
      'control_plane_container_release',
      'staging_e2e_matrix',
      'compliance_legal_signoff',
      'authorization_custody',
      'placement_confidence_staging',
      'gateway_load_abuse',
    ]);
    for (const kind of PRODUCTION_RELEASE_EVIDENCE_KINDS) {
      assert.ok(PRODUCTION_RELEASE_EVIDENCE_REQUIREMENTS[kind].length > 0);
    }
  });

  it('accepts complete evidence for every kind', () => {
    for (const kind of PRODUCTION_RELEASE_EVIDENCE_KINDS) {
      assert.deepEqual(validateProductionReleaseEvidence(kind, COMPLETE[kind]), {
        ok: true,
        invalid_kind: null,
        missing_fields: [],
        forbidden_fields: [],
        invalid_fields: [],
      });
    }
  });

  it('reports missing required fields', () => {
    const evidence = { ...COMPLETE.migration_apply };
    delete evidence.post_apply_check_uri;
    const result = validateProductionReleaseEvidence('migration_apply', evidence);
    assert.equal(result.ok, false);
    assert.deepEqual(result.missing_fields, ['post_apply_check_uri']);
  });

  it('reports missing required fields for new kinds', () => {
    const evidence = { ...COMPLETE.oidc_prod_auth_preflight };
    delete evidence.evidence_uri;
    const result = validateProductionReleaseEvidence('oidc_prod_auth_preflight', evidence);
    assert.equal(result.ok, false);
    assert.deepEqual(result.missing_fields, ['evidence_uri']);
  });

  it('reports missing required fields for production gate kinds', () => {
    const evidence = { ...COMPLETE.kms_vault_posture };
    delete evidence.evidence_uri;
    const result = validateProductionReleaseEvidence('kms_vault_posture', evidence);
    assert.equal(result.ok, false);
    assert.deepEqual(result.missing_fields, ['evidence_uri']);
  });

  it('rejects unknown evidence kinds', () => {
    const result = validateProductionReleaseEvidence('unknown_gate', {});
    assert.deepEqual(result, {
      ok: false,
      invalid_kind: 'unknown_gate',
      missing_fields: [],
      forbidden_fields: [],
      invalid_fields: [],
    });
  });

  it('rejects governed adapter partner_http adapter_type', () => {
    const evidence = { ...COMPLETE.governed_adapter, adapter_type: 'partner_http' };
    const result = validateProductionReleaseEvidence('governed_adapter', evidence);
    assert.equal(result.ok, false);
    assert.equal(
      result.invalid_fields.some((entry) => entry.field === 'adapter_type' && entry.reason === 'unsupported_adapter_type'),
      true,
    );
  });

  it('rejects governed adapter dry_run_status.traffic_generated true', () => {
    const evidence = {
      ...COMPLETE.governed_adapter,
      dry_run_status: {
        ...COMPLETE.governed_adapter.dry_run_status,
        traffic_generated: true,
      },
    };
    const result = validateProductionReleaseEvidence('governed_adapter', evidence);
    assert.equal(result.ok, false);
    assert.equal(
      result.invalid_fields.some(
        (entry) => entry.field === 'dry_run_status.traffic_generated'
          && entry.reason === 'traffic_must_not_be_generated',
      ),
      true,
    );
  });

  it('rejects kill-switch drill missing transcript closeout and SOC actor fields', () => {
    const evidence = {
      ...COMPLETE.kill_switch_drill,
      transcript: {
        activation_at: '2026-07-02T00:00:00.000Z',
        stop_signal_at: '2026-07-02T00:00:45.000Z',
        affected_request_ids: ['req-1'],
        cancelled_safe_run_ids: ['run-1'],
        soc_actors: [{ actor_id: 'soc-1' }],
        audit_event_ids: ['audit-1'],
        closeout: { signoff_by: 'soc-1' },
      },
    };
    const result = validateProductionReleaseEvidence('kill_switch_drill', evidence);
    assert.equal(result.ok, false);
    assert.ok(
      result.invalid_fields.some((entry) => entry.field === 'transcript.soc_actors[0].role'),
    );
    assert.ok(
      result.invalid_fields.some((entry) => entry.field === 'transcript.closeout.signoff_role'),
    );
  });

  it('rejects kill-switch drill latency mismatch', () => {
    const evidence = {
      ...COMPLETE.kill_switch_drill,
      response_latency_ms: 1000,
    };
    const result = validateProductionReleaseEvidence('kill_switch_drill', evidence);
    assert.equal(result.ok, false);
    assert.ok(
      result.invalid_fields.some(
        (entry) => entry.field === 'response_latency_ms' && entry.reason === 'latency_mismatch',
      ),
    );
  });

  it('rejects raw or secret-bearing evidence fields', () => {
    const evidence = {
      ...COMPLETE.operator_runbook_exercise,
      database_url: 'postgres://user:pass@example/astranull',
      attachment: { raw_log: 'contains operational details' },
    };
    const result = validateProductionReleaseEvidence('operator_runbook_exercise', evidence);
    assert.equal(result.ok, false);
    assert.deepEqual(result.forbidden_fields.sort(), ['attachment', 'attachment.raw_log', 'database_url']);
  });

  it('rejects hardened forbidden nested fields', () => {
    const cases = [
      { kind: 'governed_adapter', path: 'telemetry_metadata.packet' },
      { kind: 'kill_switch_drill', path: 'transcript.pcap' },
      { kind: 'postgres_concurrency', path: 'isolation.raw_sql' },
      { kind: 'dr_restore', path: 'backup_manifest.raw_dump' },
      { kind: 'provider_approval', path: 'legal_signoff.target_ip_inventory' },
      { kind: 'edge_protection', path: 'controls[0].api_key' },
      { kind: 'gateway_load_abuse', path: 'rate_limit_results[0].payload' },
      { kind: 'staging_e2e_matrix', path: 'scenarios[0].token' },
      { kind: 'authorization_custody', path: 'required_artifacts[0].raw_log' },
    ];
    for (const { kind, path } of cases) {
      const evidence = structuredClone(COMPLETE[kind]);
      const segments = path.split('.');
      let cursor = evidence;
      for (let i = 0; i < segments.length - 1; i += 1) {
        const segment = segments[i];
        const match = segment.match(/^(.+)\[(\d+)\]$/);
        if (match) {
          cursor = cursor[match[1]][Number(match[2])];
        } else {
          cursor = cursor[segment];
        }
      }
      const last = segments[segments.length - 1];
      cursor[last] = 'forbidden-metadata';
      const result = validateProductionReleaseEvidence(kind, evidence);
      assert.equal(result.ok, false, `${kind} should reject ${path}`);
      assert.ok(result.forbidden_fields.includes(path), `${kind} forbidden paths: ${result.forbidden_fields}`);
    }
  });

  it('allows authorized_scope_hash on provider_approval evidence', () => {
    const result = validateProductionReleaseEvidence('provider_approval', COMPLETE.provider_approval);
    assert.equal(result.ok, true);
    assert.deepEqual(result.forbidden_fields, []);
  });
});
