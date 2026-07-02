import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  ALLOWED_PROBE_PROFILE_KINDS,
  CHECK_CATALOG,
  MAX_PROBE_PROFILE_REQUESTS,
  MAX_PROBE_PROFILE_TIMEOUT_MS,
  WAF_SAFE_CHECK_IDS,
  getCheckById,
  isCustomerRunnable,
} from '../../src/contracts/checks.mjs';

/** Maps docs/progress-detailed.md VEC-* rows to versioned catalog check_ids. */
export const DETAILED_VECTOR_TRACKER = Object.freeze({
  'VEC-001': ['origin.direct_reachability.safe', 'origin.direct_bypass.safe'],
  'VEC-002': ['origin.host_sni_bypass.safe'],
  'VEC-003': ['l3.forbidden_tcp_port.safe', 'l3.forbidden_udp_port.safe'],
  'VEC-004': ['l3.basic_deny_rule.safe'],
  'VEC-005': ['dns.random_prefix_nxdomain.safe'],
  'VEC-006': ['dns.open_recursion_behavior.safe'],
  'VEC-007': [
    'l7.waf_marker_rule.safe',
    'waf.fingerprint.safe',
    'waf.marker_rule.safe',
    'waf.origin_bypass.safe',
    'waf.low_rate_limit.safe',
  ],
  'VEC-008': ['l7.low_rate_rate_limit.safe'],
  'VEC-009': ['l7.http_method_restriction.safe', 'l7.header_size_boundary.safe'],
  'VEC-010': ['tls.profile_exposure.safe'],
  'VEC-011': ['protocol.http2_readiness.safe'],
  'VEC-012': ['protocol.http3_quic_exposure.safe'],
  'VEC-013': ['ops.alert_workflow_marker.safe'],
  'VEC-014': [
    'high_scale.volumetric.request_only',
    'high_scale.application.request_only',
    'high_scale.multi_vector.request_only',
    'high_scale.degradation_recovery.request_only',
  ],
});

/** Enterprise families represented by DET-015 catalog expansion (metadata-only; no attack recipes). */
export const REQUIRED_ENTERPRISE_CHECK_IDS = Object.freeze([
  'l3.ipv6_reachability.safe',
  'l3.connection_table_exhaustion.request_only',
  'dns.amplification_exposure.safe',
  'dns.dnssec_expensive_query.safe',
  'dns.secondary_failover.safe',
  'dns.zone_transfer_exposure.safe',
  'l7.cache_busting.safe',
  'l7.expensive_endpoint.safe',
  'l7.login_abuse_flow.safe',
  'l7.password_reset.safe',
  'l7.api_quota_exhaustion.safe',
  'l7.graphql_complexity.safe',
  'l7.bot_challenge_marker.safe',
  'tls.slow_header_body_timeout.safe',
  'tls.idle_connection_timeout.safe',
  'protocol.http2_rapid_reset_readiness.safe',
  'protocol.http2_stream_concurrency.safe',
  'protocol.grpc_reflection_stream.safe',
  'protocol.websocket_connection_controls.safe',
  'ops.runbook_contact_validation.request_only',
  'ops.kill_switch_drill.request_only',
  'ops.provider_telemetry.request_only',
  'high_scale.multi_vector.request_only',
  'high_scale.degradation_recovery.request_only',
]);
import { freshStore } from '../helpers/reset.mjs';
import { startTestRun } from '../../src/services/testRuns.mjs';
import { getStore } from '../../src/store.mjs';

describe('vector catalog', () => {
  it('blocks all soc_gated checks from test-runs', () => {
    freshStore();
    const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'engineer' };
    for (const check of CHECK_CATALOG.filter((c) => c.risk_class === 'soc_gated')) {
      const result = startTestRun(ctx, {
        check_id: check.check_id,
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      });
      assert.equal(result.error, 'soc_gated_check', check.check_id);
    }
  });

  it('runs bounded safe vectors or returns prerequisite errors', () => {
    freshStore();
    const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'engineer' };
    getStore().agents.push({
      id: 'ag_1',
      tenant_id: 'ten_demo',
      status: 'online',
      capabilities: ['heartbeat', 'canary', 'packet'],
      target_group_id: 'tg_1',
    });

    for (const check of CHECK_CATALOG.filter((c) => isCustomerRunnable(c))) {
      const result = startTestRun(ctx, {
        check_id: check.check_id,
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      });
      if (result.error === 'concurrent_run_blocked') {
        getStore().testRuns.forEach((r) => {
          r.status = 'verdicted';
        });
        const retry = startTestRun(ctx, {
          check_id: check.check_id,
          target_group_id: 'tg_1',
          target_id: 'tgt_1',
        });
        assert.ok(retry.run || retry.error === 'prerequisites_not_met', check.check_id);
      } else {
        assert.ok(result.run || result.error === 'prerequisites_not_met', check.check_id);
      }
      if (result.run) {
        assert.equal(result.run.safety_class, 'safe');
        getStore().testRuns.find((r) => r.id === result.run.id).status = 'verdicted';
      }
    }
    assert.ok(getCheckById('dns.authoritative_response.safe'));
  });

  it('requires bounded probe and evidence metadata on every customer-runnable check', () => {
    for (const check of CHECK_CATALOG.filter((c) => isCustomerRunnable(c))) {
      assert.ok(Array.isArray(check.supported_targets) && check.supported_targets.length > 0, check.check_id);
      assert.ok(
        Array.isArray(check.required_customer_setup) && check.required_customer_setup.length > 0,
        check.check_id,
      );
      assert.ok(Array.isArray(check.evidence_required) && check.evidence_required.length > 0, check.check_id);
      assert.ok(Array.isArray(check.stop_conditions) && check.stop_conditions.length > 0, check.check_id);
      assert.equal(typeof check.verdict_logic, 'string');
      assert.ok(check.verdict_logic.length > 0, check.check_id);

      const constraints = check.safety_constraints;
      assert.ok(constraints && typeof constraints === 'object', check.check_id);
      assert.ok(constraints.max_events >= 1, check.check_id);
      assert.ok(constraints.max_duration_seconds >= 1, check.check_id);
      assert.equal(constraints.max_concurrent_runs_per_target_group, 1, check.check_id);

      const profile = check.probe_profile;
      assert.ok(profile && typeof profile === 'object', check.check_id);
      assert.ok(ALLOWED_PROBE_PROFILE_KINDS.includes(profile.kind), check.check_id);
      assert.ok(profile.max_requests >= 1 && profile.max_requests <= MAX_PROBE_PROFILE_REQUESTS, check.check_id);
      assert.ok(profile.timeout_ms >= 100 && profile.timeout_ms <= MAX_PROBE_PROFILE_TIMEOUT_MS, check.check_id);
      if (profile.kind === 'http_head') {
        assert.equal(profile.method, 'HEAD');
      }
    }
  });

  it('maps detailed tracker VEC-* rows to catalog check_ids (progress-detailed.md)', () => {
    for (const [vecId, checkIds] of Object.entries(DETAILED_VECTOR_TRACKER)) {
      for (const checkId of checkIds) {
        assert.ok(getCheckById(checkId), `${vecId}: missing catalog entry ${checkId}`);
      }
    }
  });

  it('keeps VEC-014 high-scale markers SOC-gated and non-customer-runnable', () => {
    for (const checkId of DETAILED_VECTOR_TRACKER['VEC-014']) {
      const check = getCheckById(checkId);
      assert.equal(isCustomerRunnable(check), false, checkId);
      assert.equal(check.risk_class, 'soc_gated', checkId);
      assert.equal(check.probe_profile, undefined, checkId);
    }
  });

  it('includes required enterprise vector check IDs (DET-015)', () => {
    for (const checkId of REQUIRED_ENTERPRISE_CHECK_IDS) {
      assert.ok(getCheckById(checkId), `missing catalog entry: ${checkId}`);
    }
  });

  it('includes required WAF-safe check IDs as customer-runnable with bounded profiles', () => {
    for (const checkId of WAF_SAFE_CHECK_IDS) {
      const check = getCheckById(checkId);
      assert.ok(check, checkId);
      assert.equal(check.safety_class, 'safe', checkId);
      assert.equal(check.risk_class, 'safe', checkId);
      assert.equal(isCustomerRunnable(check), true, checkId);
      const profile = check.probe_profile;
      assert.ok(profile.scenario_family, checkId);
      assert.ok(profile.max_requests <= MAX_PROBE_PROFILE_REQUESTS, checkId);
      assert.ok(profile.timeout_ms <= MAX_PROBE_PROFILE_TIMEOUT_MS, checkId);
    }
  });

  it('keeps soc_gated checks non-customer-runnable with governance metadata only', () => {
    for (const check of CHECK_CATALOG.filter((c) => c.risk_class === 'soc_gated')) {
      assert.equal(isCustomerRunnable(check), false, check.check_id);
      assert.equal(check.safety_class, 'soc_gated', check.check_id);
      assert.equal(check.safety_constraints?.customer_runnable, false, check.check_id);
      assert.ok(
        Array.isArray(check.required_customer_setup) && check.required_customer_setup.length > 0,
        check.check_id,
      );
      assert.ok(Array.isArray(check.evidence_required) && check.evidence_required.length > 0, check.check_id);
      assert.ok(Array.isArray(check.stop_conditions) && check.stop_conditions.length > 0, check.check_id);
      assert.equal(check.probe_profile, undefined, check.check_id);
    }
  });
});