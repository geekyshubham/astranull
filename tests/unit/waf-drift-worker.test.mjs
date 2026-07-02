import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  computeDriftSeverity,
  createDriftScanResult,
  detectConnectorConfigDrift,
  validateDriftScanResult,
} from '../../src/contracts/wafDriftWorker.mjs';
import {
  detectAssetDrift,
  getLastScanResult,
  runDriftScan,
  runScheduledDriftScans,
} from '../../src/services/wafDriftWorker.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const envSnapshot = { ...process.env };

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function wafEnabledEnv() {
  return {
    ...process.env,
    ASTRANULL_NO_PERSIST: '1',
    ASTRANULL_WAF_POSTURE_ENABLED: '1',
  };
}

function wafDisabledEnv() {
  return {
    ...process.env,
    ASTRANULL_NO_PERSIST: '1',
    ASTRANULL_WAF_POSTURE_ENABLED: '0',
  };
}

function demoCtx(tenantId = 'ten_demo') {
  return { tenantId, userId: 'usr_worker', role: 'system' };
}

function ensureWafStore() {
  const store = getStore();
  for (const key of [
    'wafAssets',
    'wafPostureSnapshots',
    'wafDriftEvents',
    'wafConnectorSnapshots',
    'wafDriftScanResults',
    'auditLog',
  ]) {
    if (!Array.isArray(store[key])) store[key] = [];
  }
  return store;
}

function seedWafAsset(overrides = {}) {
  const store = ensureWafStore();
  const asset = {
    id: 'waf_asset_1',
    tenant_id: 'ten_demo',
    target_group_id: 'tg_1',
    canonical_url: 'https://waf-app.example.com',
    expected_waf_required: true,
    status: 'protected',
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
  store.wafAssets.push(asset);
  return asset;
}

function seedConnectorSnapshots(pair) {
  const store = ensureWafStore();
  const [previous, current] = pair;
  store.wafConnectorSnapshots.push(previous, current);
}

function seedPostureSnapshots(pair) {
  const store = ensureWafStore();
  const [previous, current] = pair;
  store.wafPostureSnapshots.push(previous, current);
}

afterEach(() => {
  restoreEnv();
});

describe('connector config drift detection', () => {
  it('identifies mode downgrade, rule removal, and policy weakening', () => {
    const previous = {
      config_hash: 'sha256:prev',
      summary_json: {
        hostnames: ['waf-app.example.com'],
        policy_mode: 'blocking',
        rule_count: 150,
        managed_rule_versions: ['managed_v12', 'custom_marker_v3'],
        origin_protection_summary: 'origin_locked',
        rate_limit_summary: 'limit:100',
        security_level: 'high',
      },
    };
    const current = {
      config_hash: 'sha256:curr',
      summary_json: {
        hostnames: ['waf-app.example.com'],
        policy_mode: 'monitor',
        rule_count: 120,
        managed_rule_versions: ['managed_v12'],
        origin_protection_summary: 'allowlist_expanded',
        rate_limit_summary: 'limit:500 increased',
        security_level: 'medium',
      },
    };

    const drifts = detectConnectorConfigDrift(current, previous);
    const signals = drifts.map((d) => d.signal);

    assert.ok(signals.includes('waf_mode_changed'));
    assert.ok(signals.includes('rule_count_decreased'));
    assert.ok(signals.includes('custom_rule_removed'));
    assert.ok(signals.includes('ip_allowlist_expanded'));
    assert.ok(signals.includes('rate_limit_increased'));
    assert.ok(signals.includes('security_level_lowered'));

    for (const drift of drifts) {
      assert.match(drift.old_value_hash, /^sha256:/);
      assert.match(drift.new_value_hash, /^sha256:/);
      assert.ok(!JSON.stringify(drift).includes('blocking'));
      assert.ok(!JSON.stringify(drift).includes('monitor'));
    }
  });
});

describe('drift severity', () => {
  it('computes critical severity for mode downgrade plus rule removal', () => {
    assert.equal(
      computeDriftSeverity(['mode_downgrade', 'rule_removal']),
      'critical',
    );
  });

  it('computes medium severity for a single policy weakening change', () => {
    assert.equal(computeDriftSeverity(['policy_weakening']), 'medium');
    assert.equal(computeDriftSeverity([{ signal: 'rate_limit_increased' }]), 'medium');
  });

  it('computes high severity for certificate near expiry', () => {
    assert.equal(
      computeDriftSeverity([{ signal: 'certificate_near_expiry' }]),
      'high',
    );
    assert.equal(computeDriftSeverity(['certificate_expiry_risk']), 'high');
  });
});

describe('drift scan result validation', () => {
  it('rejects forbidden raw config fields', () => {
    assert.throws(
      () => validateDriftScanResult({
        tenant_id: 'ten_demo',
        scan_type: 'connector_config_change',
        assets_scanned: 1,
        drifts_detected: 0,
        scan_duration_ms: 10,
        completed_at: '2026-06-01T00:00:00.000Z',
        raw_config: { mode: 'off' },
      }),
      /Forbidden drift scan result field: raw_config/,
    );

    assert.throws(
      () => createDriftScanResult({
        tenant_id: 'ten_demo',
        scan_type: 'connector_config_change',
        assets_scanned: 1,
        drifts_detected: 0,
        scan_duration_ms: 5,
        completed_at: '2026-06-01T00:00:00.000Z',
        credentials: { api_key: 'secret' },
      }),
      /Forbidden drift scan result field: credentials/,
    );
  });

  it('accepts valid metadata-only scan results', () => {
    const result = createDriftScanResult({
      tenant_id: 'ten_demo',
      scan_type: 'connector_config_change',
      assets_scanned: 2,
      drifts_detected: 1,
      scan_duration_ms: 42,
      completed_at: '2026-06-01T00:00:00.000Z',
      state: 'completed',
    });
    assert.equal(result.tenant_id, 'ten_demo');
    assert.equal(result.state, 'completed');
  });
});

describe('single-asset drift check', () => {
  it('works from stored connector and posture snapshots', () => {
    Object.assign(process.env, wafEnabledEnv());
    freshStore();
    const ctx = demoCtx();
    const asset = seedWafAsset();

    seedConnectorSnapshots([
      {
        id: 'snap_prev',
        tenant_id: 'ten_demo',
        connector_id: 'conn_1',
        resource_ref_hash: 'res_hash_1',
        display_ref: 'zone/waf-app',
        config_hash: 'sha256:prev',
        observed_at: '2026-05-01T00:00:00.000Z',
        created_at: '2026-05-01T00:00:00.000Z',
        summary_json: {
          hostnames: ['waf-app.example.com'],
          policy_mode: 'blocking',
          rule_count: 140,
          managed_rule_versions: ['managed_v10', 'custom_marker_v1'],
        },
      },
      {
        id: 'snap_curr',
        tenant_id: 'ten_demo',
        connector_id: 'conn_1',
        resource_ref_hash: 'res_hash_1',
        display_ref: 'zone/waf-app',
        config_hash: 'sha256:curr',
        observed_at: '2026-06-01T00:00:00.000Z',
        created_at: '2026-06-01T00:00:00.000Z',
        summary_json: {
          hostnames: ['waf-app.example.com'],
          policy_mode: 'monitor',
          rule_count: 110,
          managed_rule_versions: ['managed_v10'],
        },
      },
    ]);

    seedPostureSnapshots([
      {
        id: 'post_prev',
        tenant_id: 'ten_demo',
        waf_asset_id: asset.id,
        status: 'protected',
        reason_codes: [],
        detected_vendor: 'cloudflare',
        detected_product: 'Cloudflare WAF',
        created_at: '2026-05-01T00:00:00.000Z',
        is_current: false,
      },
      {
        id: 'post_curr',
        tenant_id: 'ten_demo',
        waf_asset_id: asset.id,
        status: 'underprotected',
        reason_codes: ['monitor_only_behavior'],
        detected_vendor: 'cloudflare',
        detected_product: 'Cloudflare WAF',
        created_at: '2026-06-01T00:00:00.000Z',
        is_current: true,
      },
    ]);

    const outcome = detectAssetDrift(ctx, asset.id);
    assert.equal(outcome.waf_asset_id, asset.id);
    assert.ok(outcome.drifts_detected >= 2);
    assert.ok(outcome.drift_check_types.includes('mode_downgrade')
      || outcome.drift_check_types.includes('rule_removal')
      || outcome.drift_check_types.includes('policy_weakening'));

    const driftTypes = getStore().wafDriftEvents.map((e) => e.drift_type);
    assert.ok(driftTypes.includes('mode_downgrade') || driftTypes.includes('rule_removal'));
  });
});

describe('scheduled drift scans', () => {
  it('iterates tenants with WAF assets', () => {
    Object.assign(process.env, wafEnabledEnv());
    freshStore();
    seedWafAsset({ id: 'waf_a', tenant_id: 'ten_alpha' });
    seedWafAsset({ id: 'waf_b', tenant_id: 'ten_beta', canonical_url: 'https://beta.example.com' });

    const outcome = runScheduledDriftScans({ userId: 'cron', role: 'system' });
    assert.equal(outcome.tenants_scanned, 2);
    assert.equal(outcome.scan_results.length, 2);
    assert.deepEqual(
      outcome.scan_results.map((r) => r.tenant_id).sort(),
      ['ten_alpha', 'ten_beta'],
    );

    const auditActions = getStore().auditLog
      .filter((e) => e.action === 'waf.drift_scan.completed')
      .map((e) => e.tenant_id)
      .sort();
    assert.deepEqual(auditActions, ['ten_alpha', 'ten_beta']);
  });
});

describe('feature flag gating', () => {
  it('skips scan when WAF posture feature is disabled', () => {
    Object.assign(process.env, wafDisabledEnv());
    freshStore();
    seedWafAsset();

    const scan = runDriftScan(demoCtx());
    assert.equal(scan.skipped, true);
    assert.equal(scan.reason, 'waf_feature_disabled');

    const scheduled = runScheduledDriftScans();
    assert.equal(scheduled.skipped, true);
    assert.equal(scheduled.reason, 'waf_feature_disabled');

    const assetDrift = detectAssetDrift(demoCtx(), 'waf_asset_1');
    assert.equal(assetDrift.skipped, true);

    const last = getLastScanResult(demoCtx());
    assert.equal(last.skipped, true);
  });
});

describe('no outbound calls', () => {
  it('does not import or invoke network clients in drift worker code paths', () => {
    const contractSrc = readFileSync(
      path.join(process.cwd(), 'src/contracts/wafDriftWorker.mjs'),
      'utf8',
    );
    const serviceSrc = readFileSync(
      path.join(process.cwd(), 'src/services/wafDriftWorker.mjs'),
      'utf8',
    );
    const forbidden = [
      /\bfetch\s*\(/,
      /\bhttp\.request\s*\(/,
      /\bhttps\.request\s*\(/,
      /\bnet\.connect\s*\(/,
      /\bdns\.lookup\s*\(/,
      /from\s+['"]node:https['"]/,
      /from\s+['"]node:http['"]/,
      /from\s+['"]node:net['"]/,
      /from\s+['"]node:dns/,
    ];

    for (const pattern of forbidden) {
      assert.ok(!pattern.test(contractSrc), `contract must not match ${pattern}`);
      assert.ok(!pattern.test(serviceSrc), `service must not match ${pattern}`);
    }
  });

  it('records scan results without outbound calls', () => {
    Object.assign(process.env, wafEnabledEnv());
    freshStore();
    seedWafAsset();

    const outcome = runDriftScan(demoCtx());
    assert.ok(outcome.scan_result);
    const last = getLastScanResult(demoCtx());
    assert.equal(last.scan_result.tenant_id, 'ten_demo');
    assert.equal(last.scan_result.assets_scanned, 1);
  });
});