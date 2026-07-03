import { runWithTenantClient, withTenantContext } from './tenantContext.mjs';

const WAF_ASSET_COLUMNS = `id, tenant_id, target_group_id, target_id, environment_id, canonical_url,
  asset_kind, expected_waf_required, expected_vendor_hint, business_criticality, traffic_tier,
  compliance_tags, owner_hint, region_code, geography_label, entity_id, owasp_exposure_tags,
  created_at, updated_at`;

const WAF_VALIDATION_RUN_COLUMNS = `id, tenant_id, test_run_id, waf_asset_id, mode, status,
  started_at, finalized_at, safety_profile_json, summary_json, created_at`;

const WAF_SCENARIO_RESULT_COLUMNS = `id, tenant_id, waf_validation_run_id, scenario_family,
  test_material_type, expected_action, observed_action, passed, confidence,
  evidence_summary_json, created_at`;

const WAF_POSTURE_SNAPSHOT_COLUMNS = `id, tenant_id, waf_asset_id, status, reason_codes,
  detected_vendor, detected_product, coverage_required, risk_score, risk_factors_json,
  priority_band, recommended_action, scenario_pass_rate, control_bypass_status, confidence,
  source_mix_json, created_at, is_current`;

const WAF_COVERAGE_DAILY_ROLLUP_COLUMNS = `id, tenant_id, rollup_date, total_assets, protected,
  underprotected, unprotected, unknown, excluded, coverage_ratio, created_at`;

const FINDING_COLUMNS = `id, tenant_id, target_group_id, target_id, test_run_id, check_id, title, severity,
  status, evidence_ids, notes, remediation_template, verdict_id, last_verdict_id, assignee,
  created_at, updated_at`;

const WAF_DRIFT_EVENT_COLUMNS = `id, tenant_id, waf_asset_id, baseline_id, drift_type, severity,
  before_summary_json, after_summary_json, status, finding_id, created_at, resolved_at`;

const WAF_DRIFT_SCAN_RESULT_COLUMNS = `id, tenant_id, scan_type, assets_scanned, drifts_detected,
  scan_duration_ms, completed_at, state, assets_with_connector_snapshots, drift_check_types, created_at`;

const WAF_CONNECTOR_COLUMNS = `id, tenant_id, provider, name, secret_id, config_json, status,
  last_success_at, last_error_at, created_at, updated_at`;

const WAF_CONNECTOR_SNAPSHOT_COLUMNS = `id, tenant_id, connector_id, provider, snapshot_kind,
  resource_ref_hash, display_ref, summary_json, config_hash, observed_at, created_at`;

function asStringArray(value) {
  return Array.isArray(value) ? value : [];
}

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

export function mapWafAssetRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    target_group_id: row.target_group_id,
    target_id: row.target_id ?? null,
    environment_id: row.environment_id ?? null,
    canonical_url: row.canonical_url,
    asset_kind: row.asset_kind ?? 'unknown',
    expected_waf_required: row.expected_waf_required !== false,
    expected_vendor_hint: row.expected_vendor_hint ?? null,
    business_criticality: row.business_criticality ?? 'medium',
    traffic_tier: row.traffic_tier ?? 'unknown',
    compliance_tags: row.compliance_tags ?? [],
    owner_hint: row.owner_hint ?? null,
    region_code: row.region_code ?? null,
    geography_label: row.geography_label ?? null,
    entity_id: row.entity_id ?? null,
    owasp_exposure_tags: row.owasp_exposure_tags ?? [],
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
  };
}

export function mapWafValidationRunRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    test_run_id: row.test_run_id ?? null,
    waf_asset_id: row.waf_asset_id,
    mode: row.mode,
    status: row.status,
    started_at: row.started_at == null ? null : toIso(row.started_at),
    finalized_at: row.finalized_at == null ? null : toIso(row.finalized_at),
    safety_profile_json: row.safety_profile_json ?? {},
    summary_json: row.summary_json ?? {},
    created_at: toIso(row.created_at),
  };
}

export function mapWafScenarioResultRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    waf_validation_run_id: row.waf_validation_run_id,
    scenario_family: row.scenario_family,
    test_material_type: row.test_material_type ?? 'metadata_only',
    expected_action: row.expected_action,
    observed_action: row.observed_action ?? 'inconclusive',
    passed: row.passed ?? null,
    confidence: Number(row.confidence ?? 0),
    evidence_summary_json: row.evidence_summary_json ?? {},
    created_at: toIso(row.created_at),
  };
}

export function mapWafPostureSnapshotRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    waf_asset_id: row.waf_asset_id,
    status: row.status,
    reason_codes: row.reason_codes ?? [],
    detected_vendor: row.detected_vendor ?? null,
    detected_product: row.detected_product ?? null,
    coverage_required: row.coverage_required !== false,
    risk_score: Number(row.risk_score ?? 0),
    risk_factors_json: Array.isArray(row.risk_factors_json) ? row.risk_factors_json : [],
    priority_band: row.priority_band ?? null,
    recommended_action: row.recommended_action ?? null,
    scenario_pass_rate: row.scenario_pass_rate == null ? null : Number(row.scenario_pass_rate),
    control_bypass_status: row.control_bypass_status ?? null,
    confidence: Number(row.confidence ?? 0),
    source_mix_json: row.source_mix_json ?? {},
    created_at: toIso(row.created_at),
    is_current: row.is_current === true,
  };
}

export function mapWafPostureFindingRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    target_group_id: row.target_group_id ?? null,
    target_id: row.target_id ?? null,
    test_run_id: row.test_run_id ?? null,
    check_id: row.check_id ?? null,
    title: row.title,
    severity: row.severity,
    status: row.status,
    evidence_ids: asStringArray(row.evidence_ids),
    notes: row.notes ?? null,
    remediation_template: row.remediation_template ?? null,
    verdict_id: row.verdict_id ?? null,
    last_verdict_id: row.last_verdict_id ?? null,
    assignee: row.assignee ?? null,
    created_at: toIso(row.created_at),
    updated_at: row.updated_at == null ? null : toIso(row.updated_at),
  };
}

export function mapWafDriftEventRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    waf_asset_id: row.waf_asset_id,
    baseline_id: row.baseline_id ?? null,
    drift_type: row.drift_type,
    severity: row.severity,
    before_summary: row.before_summary_json ?? {},
    after_summary: row.after_summary_json ?? {},
    status: row.status,
    finding_id: row.finding_id ?? null,
    created_at: toIso(row.created_at),
    resolved_at: row.resolved_at == null ? null : toIso(row.resolved_at),
  };
}

export function mapWafCoverageDailyRollupRow(row) {
  if (!row) return null;
  const rollupDate = row.rollup_date instanceof Date
    ? row.rollup_date.toISOString().slice(0, 10)
    : String(row.rollup_date ?? '').slice(0, 10);
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    rollup_date: rollupDate,
    total_assets: Number(row.total_assets ?? 0),
    protected: Number(row.protected ?? 0),
    underprotected: Number(row.underprotected ?? 0),
    unprotected: Number(row.unprotected ?? 0),
    unknown: Number(row.unknown ?? 0),
    excluded: Number(row.excluded ?? 0),
    coverage_ratio: Number(row.coverage_ratio ?? 0),
    created_at: toIso(row.created_at),
  };
}

export function mapWafDriftScanResultRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    scan_type: row.scan_type,
    assets_scanned: Number(row.assets_scanned ?? 0),
    drifts_detected: Number(row.drifts_detected ?? 0),
    scan_duration_ms: Number(row.scan_duration_ms ?? 0),
    completed_at: toIso(row.completed_at),
    state: row.state ?? 'completed',
    ...(row.assets_with_connector_snapshots == null
      ? {}
      : { assets_with_connector_snapshots: Number(row.assets_with_connector_snapshots) }),
    drift_check_types: row.drift_check_types ?? [],
    created_at: toIso(row.created_at),
  };
}

export function formatDriftEventForApi(driftEvent) {
  if (!driftEvent) return null;
  return {
    id: driftEvent.id,
    waf_asset_id: driftEvent.waf_asset_id,
    baseline_id: driftEvent.baseline_id ?? null,
    drift_type: driftEvent.drift_type,
    severity: driftEvent.severity,
    before_summary: driftEvent.before_summary ?? driftEvent.before_summary_json ?? {},
    after_summary: driftEvent.after_summary ?? driftEvent.after_summary_json ?? {},
    status: driftEvent.status,
    finding_id: driftEvent.finding_id ?? null,
    created_at: driftEvent.created_at,
    resolved_at: driftEvent.resolved_at ?? null,
  };
}

export function mapWafConnectorRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    provider: row.provider,
    name: row.name,
    secret_id: row.secret_id ?? null,
    config: row.config_json ?? {},
    status: row.status,
    last_success_at: row.last_success_at == null ? null : toIso(row.last_success_at),
    last_error_at: row.last_error_at == null ? null : toIso(row.last_error_at),
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
  };
}

export function mapWafConnectorSnapshotRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    connector_id: row.connector_id,
    provider: row.provider,
    snapshot_kind: row.snapshot_kind,
    resource_ref_hash: row.resource_ref_hash,
    display_ref: row.display_ref ?? null,
    summary: row.summary_json ?? {},
    config_hash: row.config_hash ?? null,
    observed_at: toIso(row.observed_at),
    created_at: toIso(row.created_at),
  };
}

export function formatConnectorForApi(connector) {
  if (!connector) return null;
  return {
    id: connector.id,
    provider: connector.provider,
    name: connector.name,
    secret_id: connector.secret_id ?? null,
    config: connector.config ?? connector.config_json ?? {},
    status: connector.status,
    last_success_at: connector.last_success_at ?? null,
    last_error_at: connector.last_error_at ?? null,
    created_at: connector.created_at,
    updated_at: connector.updated_at,
  };
}

export function formatConnectorSnapshotForApi(snapshot) {
  if (!snapshot) return null;
  return {
    id: snapshot.id,
    connector_id: snapshot.connector_id,
    provider: snapshot.provider,
    snapshot_kind: snapshot.snapshot_kind,
    resource_ref_hash: snapshot.resource_ref_hash,
    display_ref: snapshot.display_ref ?? null,
    summary: snapshot.summary ?? snapshot.summary_json ?? {},
    config_hash: snapshot.config_hash ?? null,
    observed_at: snapshot.observed_at,
    created_at: snapshot.created_at,
  };
}

export function formatPostureSnapshotForApi(snapshot) {
  if (!snapshot) return null;
  return {
    id: snapshot.id,
    waf_asset_id: snapshot.waf_asset_id,
    status: snapshot.status,
    reason_codes: snapshot.reason_codes ?? [],
    detected_vendor: snapshot.detected_vendor ?? null,
    detected_product: snapshot.detected_product ?? null,
    coverage_required: snapshot.coverage_required,
    risk_score: snapshot.risk_score,
    ...(Array.isArray(snapshot.risk_factors_json) ? { risk_factors: snapshot.risk_factors_json } : {}),
    ...(snapshot.priority_band ? { priority_band: snapshot.priority_band } : {}),
    ...(snapshot.recommended_action ? { recommended_action: snapshot.recommended_action } : {}),
    confidence: snapshot.confidence,
    source_mix: snapshot.source_mix_json ?? {},
    created_at: snapshot.created_at,
    is_current: snapshot.is_current,
  };
}

export function createWafPostureRepository(pool) {
  return {
    async listWafAssets(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${WAF_ASSET_COLUMNS}
           FROM waf_assets
           WHERE tenant_id = $1
           ORDER BY created_at ASC`,
          [tenantId],
        );
        return rows.map(mapWafAssetRow);
      });
    },

    async createWafAsset(ctx, record) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO waf_assets (
             id, tenant_id, target_group_id, target_id, environment_id, canonical_url,
             asset_kind, expected_waf_required, expected_vendor_hint, business_criticality,
             traffic_tier, compliance_tags, owner_hint, region_code, geography_label, entity_id,
             owasp_exposure_tags, created_at, updated_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
             $18::timestamptz, $19::timestamptz)
           RETURNING ${WAF_ASSET_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.target_group_id,
            record.target_id ?? null,
            record.environment_id ?? null,
            record.canonical_url,
            record.asset_kind ?? 'unknown',
            record.expected_waf_required !== false,
            record.expected_vendor_hint ?? null,
            record.business_criticality ?? 'medium',
            record.traffic_tier ?? 'unknown',
            record.compliance_tags ?? [],
            record.owner_hint ?? null,
            record.region_code ?? null,
            record.geography_label ?? null,
            record.entity_id ?? null,
            record.owasp_exposure_tags ?? [],
            record.created_at,
            record.updated_at,
          ],
        );
        return mapWafAssetRow(rows[0]);
      });
    },

    async getWafAsset(ctx, id, options = {}) {
      const tenantId = ctx.tenantId;
      return runWithTenantClient(pool, tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `SELECT ${WAF_ASSET_COLUMNS}
           FROM waf_assets
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        return mapWafAssetRow(rows[0] ?? null);
      });
    },

    async updateWafAsset(ctx, id, updates) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE waf_assets
           SET target_id = COALESCE($3, target_id),
               asset_kind = COALESCE($4, asset_kind),
               canonical_url = COALESCE($5, canonical_url),
               expected_waf_required = COALESCE($6, expected_waf_required),
               expected_vendor_hint = COALESCE($7, expected_vendor_hint),
               business_criticality = COALESCE($8, business_criticality),
               traffic_tier = COALESCE($9, traffic_tier),
               compliance_tags = COALESCE($10, compliance_tags),
               owner_hint = COALESCE($11, owner_hint),
               region_code = COALESCE($12, region_code),
               geography_label = COALESCE($13, geography_label),
               entity_id = COALESCE($14, entity_id),
               owasp_exposure_tags = COALESCE($15, owasp_exposure_tags),
               updated_at = $16::timestamptz
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${WAF_ASSET_COLUMNS}`,
          [
            tenantId,
            id,
            updates.target_id,
            updates.asset_kind,
            updates.canonical_url,
            updates.expected_waf_required,
            updates.expected_vendor_hint,
            updates.business_criticality,
            updates.traffic_tier,
            updates.compliance_tags,
            updates.owner_hint,
            updates.region_code,
            updates.geography_label,
            updates.entity_id,
            updates.owasp_exposure_tags,
            updates.updated_at,
          ],
        );
        return mapWafAssetRow(rows[0] ?? null);
      });
    },

    async listCurrentPostureSnapshots(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${WAF_POSTURE_SNAPSHOT_COLUMNS}
           FROM waf_posture_snapshots
           WHERE tenant_id = $1 AND is_current = TRUE`,
          [tenantId],
        );
        return rows.map(mapWafPostureSnapshotRow);
      });
    },

    async getCurrentPostureSnapshot(ctx, wafAssetId) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${WAF_POSTURE_SNAPSHOT_COLUMNS}
           FROM waf_posture_snapshots
           WHERE tenant_id = $1 AND waf_asset_id = $2 AND is_current = TRUE
           ORDER BY created_at DESC
           LIMIT 1`,
          [tenantId, wafAssetId],
        );
        return mapWafPostureSnapshotRow(rows[0] ?? null);
      });
    },

    async listPostureSnapshotsSince(ctx, sinceIso) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${WAF_POSTURE_SNAPSHOT_COLUMNS}
           FROM waf_posture_snapshots
           WHERE tenant_id = $1 AND created_at >= $2::timestamptz
           ORDER BY created_at ASC`,
          [tenantId, sinceIso],
        );
        return rows.map(mapWafPostureSnapshotRow);
      });
    },

    async listLatestValidationSummariesByAsset(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT DISTINCT ON (waf_asset_id)
              waf_asset_id, summary_json
           FROM waf_validation_runs
           WHERE tenant_id = $1 AND status = 'finalized'
           ORDER BY waf_asset_id, finalized_at DESC NULLS LAST, created_at DESC`,
          [tenantId],
        );
        const map = new Map();
        for (const row of rows) {
          map.set(row.waf_asset_id, row.summary_json ?? {});
        }
        return map;
      });
    },

    async listTenantCveAssetMatches(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT m.id, m.waf_asset_id, m.validation_status, m.risk_score,
                  i.known_exploited, i.state AS pipeline_state
           FROM cve_asset_matches m
           LEFT JOIN cve_pipeline_items i
             ON i.tenant_id = m.tenant_id AND i.id = m.cve_pipeline_item_id
           WHERE m.tenant_id = $1 AND m.waf_asset_id IS NOT NULL`,
          [tenantId],
        );
        const map = new Map();
        for (const row of rows) {
          const assetId = row.waf_asset_id;
          const bucket = map.get(assetId) ?? [];
          bucket.push({
            id: row.id,
            waf_asset_id: assetId,
            validation_status: row.validation_status,
            status: row.pipeline_state,
            risk_score: Number(row.risk_score ?? 0),
            known_exploited: row.known_exploited === true,
          });
          map.set(assetId, bucket);
        }
        return map;
      });
    },

    async listWafFindingIdsByAsset(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, check_id
           FROM findings
           WHERE tenant_id = $1 AND check_id LIKE 'waf.posture.%'`,
          [tenantId],
        );
        const map = new Map();
        for (const row of rows) {
          const assetId = String(row.check_id).replace(/^waf\.posture\./, '');
          const bucket = map.get(assetId) ?? [];
          bucket.push(row.id);
          map.set(assetId, bucket);
        }
        return map;
      });
    },

    async listWafActionItemIdsByAsset(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, waf_asset_id
           FROM waf_action_items
           WHERE tenant_id = $1 AND waf_asset_id IS NOT NULL`,
          [tenantId],
        );
        const map = new Map();
        for (const row of rows) {
          const bucket = map.get(row.waf_asset_id) ?? [];
          bucket.push(row.id);
          map.set(row.waf_asset_id, bucket);
        }
        return map;
      });
    },

    async listWafValidationRuns(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${WAF_VALIDATION_RUN_COLUMNS}
           FROM waf_validation_runs
           WHERE tenant_id = $1
           ORDER BY created_at ASC`,
          [tenantId],
        );
        return rows.map(mapWafValidationRunRow);
      });
    },

    async createWafValidationRun(ctx, record, options = {}) {
      const tenantId = ctx.tenantId;
      return runWithTenantClient(pool, tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO waf_validation_runs (
             id, tenant_id, test_run_id, waf_asset_id, mode, status,
             safety_profile_json, summary_json, created_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9::timestamptz)
           RETURNING ${WAF_VALIDATION_RUN_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.test_run_id ?? null,
            record.waf_asset_id,
            record.mode,
            record.status ?? 'planned',
            JSON.stringify(record.safety_profile_json ?? {}),
            JSON.stringify(record.summary_json ?? {}),
            record.created_at,
          ],
        );
        return mapWafValidationRunRow(rows[0]);
      });
    },

    async getWafValidationRun(ctx, id, options = {}) {
      const tenantId = ctx.tenantId;
      return runWithTenantClient(pool, tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `SELECT ${WAF_VALIDATION_RUN_COLUMNS}
           FROM waf_validation_runs
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        return mapWafValidationRunRow(rows[0] ?? null);
      });
    },

    async listWafScenarioResultsForRun(ctx, wafValidationRunId) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${WAF_SCENARIO_RESULT_COLUMNS}
           FROM waf_scenario_results
           WHERE tenant_id = $1 AND waf_validation_run_id = $2
           ORDER BY created_at ASC`,
          [tenantId, wafValidationRunId],
        );
        return rows.map(mapWafScenarioResultRow);
      });
    },

    async finalizeWafValidationBundle(ctx, bundle) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        await client.query(
          `UPDATE waf_posture_snapshots
           SET is_current = FALSE
           WHERE tenant_id = $1 AND waf_asset_id = $2 AND is_current = TRUE`,
          [tenantId, bundle.waf_asset_id],
        );

        const snapshot = bundle.snapshot;
        await client.query(
          `INSERT INTO waf_posture_snapshots (
             id, tenant_id, waf_asset_id, status, reason_codes, detected_vendor, detected_product,
             coverage_required, risk_score, risk_factors_json, priority_band, recommended_action,
             scenario_pass_rate, control_bypass_status, confidence, source_mix_json, created_at,
             is_current
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12, $13, $14, $15, $16::jsonb,
             $17::timestamptz, TRUE)`,
          [
            snapshot.id,
            tenantId,
            bundle.waf_asset_id,
            snapshot.status,
            snapshot.reason_codes ?? [],
            snapshot.detected_vendor ?? null,
            snapshot.detected_product ?? null,
            snapshot.coverage_required !== false,
            snapshot.risk_score ?? 0,
            JSON.stringify(snapshot.risk_factors_json ?? []),
            snapshot.priority_band ?? null,
            snapshot.recommended_action ?? null,
            snapshot.scenario_pass_rate ?? null,
            snapshot.control_bypass_status ?? null,
            snapshot.confidence ?? 0,
            JSON.stringify(snapshot.source_mix_json ?? {}),
            snapshot.created_at,
          ],
        );

        for (const scenario of bundle.scenarios) {
          await client.query(
            `INSERT INTO waf_scenario_results (
               id, tenant_id, waf_validation_run_id, scenario_family, test_material_type,
               expected_action, observed_action, passed, confidence, evidence_summary_json, created_at
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::timestamptz)`,
            [
              scenario.id,
              tenantId,
              bundle.run_id,
              scenario.scenario_family,
              scenario.test_material_type ?? 'metadata_only',
              scenario.expected_action,
              scenario.observed_action ?? 'inconclusive',
              scenario.passed ?? null,
              scenario.confidence ?? 0,
              JSON.stringify(scenario.evidence_summary_json ?? {}),
              scenario.created_at,
            ],
          );
        }

        const run = bundle.run_updates;
        const { rows: runRows } = await client.query(
          `UPDATE waf_validation_runs
           SET status = $3,
               finalized_at = $4::timestamptz,
               summary_json = $5::jsonb
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${WAF_VALIDATION_RUN_COLUMNS}`,
          [
            tenantId,
            bundle.run_id,
            run.status,
            run.finalized_at,
            JSON.stringify(run.summary_json ?? {}),
          ],
        );

        await client.query(
          `UPDATE waf_assets
           SET updated_at = $3::timestamptz
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, bundle.waf_asset_id, bundle.asset_updated_at],
        );

        return {
          validation_run: mapWafValidationRunRow(runRows[0] ?? null),
          snapshot: mapWafPostureSnapshotRow({
            ...snapshot,
            tenant_id: tenantId,
            waf_asset_id: bundle.waf_asset_id,
            is_current: true,
          }),
        };
      });
    },

    async upsertWafPostureFinding(ctx, record) {
      const tenantId = ctx.tenantId;
      const evidenceIds = asStringArray(record.evidence_ids);
      const updatedAt = record.updated_at ?? new Date().toISOString();

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows: existingRows } = await client.query(
          `SELECT ${FINDING_COLUMNS}
           FROM findings
           WHERE tenant_id = $1
             AND target_group_id = $2
             AND target_id IS NOT DISTINCT FROM $3
             AND check_id = $4
             AND status = 'open'`,
          [
            tenantId,
            record.target_group_id,
            record.target_id ?? null,
            record.check_id,
          ],
        );
        const existing = existingRows[0] ?? null;

        if (existing) {
          const { rows } = await client.query(
            `UPDATE findings
             SET title = $3,
                 severity = $4,
                 test_run_id = $5,
                 evidence_ids = $6,
                 notes = $7,
                 remediation_template = $8,
                 last_verdict_id = NULL,
                 updated_at = $9::timestamptz
             WHERE tenant_id = $1 AND id = $2
             RETURNING ${FINDING_COLUMNS}`,
            [
              tenantId,
              existing.id,
              record.title,
              record.severity,
              record.test_run_id ?? null,
              evidenceIds,
              record.notes ?? null,
              record.remediation_template ?? null,
              updatedAt,
            ],
          );
          return { finding: mapWafPostureFindingRow(rows[0]), inserted: false };
        }

        const { rows } = await client.query(
          `INSERT INTO findings (
             id, tenant_id, target_group_id, target_id, test_run_id, check_id, title, severity,
             status, evidence_ids, notes, remediation_template, verdict_id, last_verdict_id,
             assignee, created_at, updated_at
           )
           VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
             $16::timestamptz, $17::timestamptz
           )
           RETURNING ${FINDING_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.target_group_id,
            record.target_id ?? null,
            record.test_run_id ?? null,
            record.check_id,
            record.title,
            record.severity,
            record.status ?? 'open',
            evidenceIds,
            record.notes ?? null,
            record.remediation_template ?? null,
            record.verdict_id ?? null,
            null,
            record.assignee ?? null,
            record.created_at,
            updatedAt,
          ],
        );
        return { finding: mapWafPostureFindingRow(rows[0]), inserted: true };
      });
    },

    async listWafDriftEvents(ctx, options = {}) {
      const tenantId = ctx.tenantId;
      const limit = Number.isFinite(Number(options.limit)) && Number(options.limit) > 0
        ? Math.floor(Number(options.limit))
        : null;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          limit
            ? `SELECT ${WAF_DRIFT_EVENT_COLUMNS}
               FROM waf_drift_events
               WHERE tenant_id = $1
               ORDER BY created_at DESC
               LIMIT $2`
            : `SELECT ${WAF_DRIFT_EVENT_COLUMNS}
               FROM waf_drift_events
               WHERE tenant_id = $1
               ORDER BY created_at DESC`,
          limit ? [tenantId, limit] : [tenantId],
        );
        return rows.map(mapWafDriftEventRow);
      });
    },

    async upsertWafDriftEvent(ctx, record) {
      const tenantId = ctx.tenantId;
      const createdAt = record.created_at ?? new Date().toISOString();
      const beforeSummary = record.before_summary ?? record.before_summary_json ?? {};
      const afterSummary = record.after_summary ?? record.after_summary_json ?? {};

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows: existingRows } = await client.query(
          `SELECT ${WAF_DRIFT_EVENT_COLUMNS}
           FROM waf_drift_events
           WHERE tenant_id = $1
             AND waf_asset_id = $2
             AND drift_type = $3
             AND status = 'open'`,
          [tenantId, record.waf_asset_id, record.drift_type],
        );
        const existing = existingRows[0] ?? null;

        if (existing) {
          const { rows } = await client.query(
            `UPDATE waf_drift_events
             SET severity = $3,
                 before_summary_json = $4::jsonb,
                 after_summary_json = $5::jsonb,
                 finding_id = $6,
                 created_at = $7::timestamptz
             WHERE tenant_id = $1 AND id = $2
             RETURNING ${WAF_DRIFT_EVENT_COLUMNS}`,
            [
              tenantId,
              existing.id,
              record.severity ?? 'medium',
              JSON.stringify(beforeSummary),
              JSON.stringify(afterSummary),
              record.finding_id ?? null,
              createdAt,
            ],
          );
          return { drift_event: mapWafDriftEventRow(rows[0]), inserted: false };
        }

        const { rows } = await client.query(
          `INSERT INTO waf_drift_events (
             id, tenant_id, waf_asset_id, baseline_id, drift_type, severity,
             before_summary_json, after_summary_json, status, finding_id, created_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10, $11::timestamptz)
           RETURNING ${WAF_DRIFT_EVENT_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.waf_asset_id,
            record.baseline_id ?? null,
            record.drift_type,
            record.severity ?? 'medium',
            JSON.stringify(beforeSummary),
            JSON.stringify(afterSummary),
            record.status ?? 'open',
            record.finding_id ?? null,
            createdAt,
          ],
        );
        return { drift_event: mapWafDriftEventRow(rows[0]), inserted: true };
      });
    },

    async patchWafDriftEvent(ctx, id, updates) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE waf_drift_events
           SET status = COALESCE($3, status),
               resolved_at = $4::timestamptz
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${WAF_DRIFT_EVENT_COLUMNS}`,
          [
            tenantId,
            id,
            updates.status,
            updates.resolved_at ?? null,
          ],
        );
        return mapWafDriftEventRow(rows[0] ?? null);
      });
    },

    async listConnectors(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${WAF_CONNECTOR_COLUMNS}
           FROM waf_connectors
           WHERE tenant_id = $1
           ORDER BY created_at ASC`,
          [tenantId],
        );
        return rows.map(mapWafConnectorRow);
      });
    },

    async createConnector(ctx, record) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO waf_connectors (
             id, tenant_id, provider, name, secret_id, config_json, status,
             created_at, updated_at
           )
           VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8::timestamptz, $9::timestamptz)
           RETURNING ${WAF_CONNECTOR_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.provider,
            record.name,
            record.secret_id ?? null,
            JSON.stringify(record.config_json ?? {}),
            record.status ?? 'disabled',
            record.created_at,
            record.updated_at,
          ],
        );
        return mapWafConnectorRow(rows[0]);
      });
    },

    async getConnector(ctx, id) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${WAF_CONNECTOR_COLUMNS}
           FROM waf_connectors
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        return mapWafConnectorRow(rows[0] ?? null);
      });
    },

    async updateConnectorStatus(ctx, id, updates) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const setClauses = ['updated_at = $3::timestamptz'];
        const params = [tenantId, id, updates.updated_at];
        let paramIndex = 4;
        if (updates.status !== undefined) {
          setClauses.push(`status = $${paramIndex}`);
          params.push(updates.status);
          paramIndex += 1;
        }
        if (updates.last_success_at !== undefined) {
          setClauses.push(`last_success_at = $${paramIndex}::timestamptz`);
          params.push(updates.last_success_at);
          paramIndex += 1;
        }
        if (Object.prototype.hasOwnProperty.call(updates, 'last_error_at')) {
          setClauses.push(`last_error_at = $${paramIndex}::timestamptz`);
          params.push(updates.last_error_at);
          paramIndex += 1;
        }
        const { rows } = await client.query(
          `UPDATE waf_connectors
           SET ${setClauses.join(', ')}
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${WAF_CONNECTOR_COLUMNS}`,
          params,
        );
        return mapWafConnectorRow(rows[0] ?? null);
      });
    },

    async createConnectorSnapshots(ctx, records) {
      const tenantId = ctx.tenantId;
      if (!Array.isArray(records) || records.length === 0) {
        return [];
      }
      return withTenantContext(pool, tenantId, async (client) => {
        const persisted = [];
        for (const record of records) {
          const { rows } = await client.query(
            `INSERT INTO waf_connector_snapshots (
               id, tenant_id, connector_id, provider, snapshot_kind, resource_ref_hash,
               display_ref, summary_json, config_hash, observed_at, created_at
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10::timestamptz, $11::timestamptz)
             RETURNING ${WAF_CONNECTOR_SNAPSHOT_COLUMNS}`,
            [
              record.id,
              tenantId,
              record.connector_id,
              record.provider,
              record.snapshot_kind,
              record.resource_ref_hash,
              record.display_ref ?? null,
              JSON.stringify(record.summary_json ?? {}),
              record.config_hash ?? null,
              record.observed_at,
              record.created_at,
            ],
          );
          persisted.push(mapWafConnectorSnapshotRow(rows[0]));
        }
        return persisted;
      });
    },

    async listConnectorSnapshots(ctx, connectorId) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${WAF_CONNECTOR_SNAPSHOT_COLUMNS}
           FROM waf_connector_snapshots
           WHERE tenant_id = $1 AND connector_id = $2
           ORDER BY observed_at DESC`,
          [tenantId, connectorId],
        );
        return rows.map(mapWafConnectorSnapshotRow);
      });
    },

    async listWafConnectorSnapshotsForTenant(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${WAF_CONNECTOR_SNAPSHOT_COLUMNS}
           FROM waf_connector_snapshots
           WHERE tenant_id = $1
           ORDER BY observed_at DESC, created_at DESC`,
          [tenantId],
        );
        return rows.map(mapWafConnectorSnapshotRow);
      });
    },

    async listWafPostureSnapshotsForTenant(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${WAF_POSTURE_SNAPSHOT_COLUMNS}
           FROM waf_posture_snapshots
           WHERE tenant_id = $1
           ORDER BY created_at DESC`,
          [tenantId],
        );
        return rows.map(mapWafPostureSnapshotRow);
      });
    },

    async createWafDriftScanResult(ctx, record) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO waf_drift_scan_results (
             id, tenant_id, scan_type, assets_scanned, drifts_detected, scan_duration_ms,
             completed_at, state, assets_with_connector_snapshots, drift_check_types, created_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz, $8, $9, $10, $11::timestamptz)
           RETURNING ${WAF_DRIFT_SCAN_RESULT_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.scan_type,
            record.assets_scanned ?? 0,
            record.drifts_detected ?? 0,
            record.scan_duration_ms ?? 0,
            record.completed_at,
            record.state ?? 'completed',
            record.assets_with_connector_snapshots ?? null,
            record.drift_check_types ?? [],
            record.created_at ?? record.completed_at,
          ],
        );
        return mapWafDriftScanResultRow(rows[0]);
      });
    },

    async getLatestWafDriftScanResult(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${WAF_DRIFT_SCAN_RESULT_COLUMNS}
           FROM waf_drift_scan_results
           WHERE tenant_id = $1
           ORDER BY completed_at DESC, created_at DESC
           LIMIT 1`,
          [tenantId],
        );
        return mapWafDriftScanResultRow(rows[0] ?? null);
      });
    },

    async listWafScenarioIntakes(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, pattern_title, advisory_refs, proposed_scenario_family,
                  risk_class, intake_stage, notes, threat_summary, created_at, updated_at
           FROM waf_scenario_intakes
           WHERE tenant_id = $1
           ORDER BY created_at DESC`,
          [tenantId],
        );
        return rows.map((row) => ({
          id: row.id,
          tenant_id: row.tenant_id,
          pattern_title: row.pattern_title,
          advisory_refs: row.advisory_refs ?? [],
          proposed_scenario_family: row.proposed_scenario_family ?? null,
          risk_class: row.risk_class,
          intake_stage: row.intake_stage,
          notes: row.notes ?? null,
          threat_summary: row.threat_summary ?? null,
          created_at: toIso(row.created_at),
          updated_at: toIso(row.updated_at),
        }));
      });
    },

    async insertWafScenarioIntake(ctx, record) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO waf_scenario_intakes (
             id, tenant_id, pattern_title, advisory_refs, proposed_scenario_family,
             risk_class, intake_stage, notes, threat_summary, created_at, updated_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::timestamptz, $11::timestamptz)
           RETURNING id, tenant_id, pattern_title, advisory_refs, proposed_scenario_family,
                     risk_class, intake_stage, notes, threat_summary, created_at, updated_at`,
          [
            record.id,
            tenantId,
            record.pattern_title,
            record.advisory_refs ?? [],
            record.proposed_scenario_family ?? null,
            record.risk_class,
            record.intake_stage,
            record.notes ?? null,
            record.threat_summary ?? null,
            record.created_at,
            record.updated_at,
          ],
        );
        const row = rows[0];
        return {
          id: row.id,
          tenant_id: row.tenant_id,
          pattern_title: row.pattern_title,
          advisory_refs: row.advisory_refs ?? [],
          proposed_scenario_family: row.proposed_scenario_family ?? null,
          risk_class: row.risk_class,
          intake_stage: row.intake_stage,
          notes: row.notes ?? null,
          threat_summary: row.threat_summary ?? null,
          created_at: toIso(row.created_at),
          updated_at: toIso(row.updated_at),
        };
      });
    },

    async upsertWafCoverageDailyRollup(ctx, record) {
      const tenantId = ctx.tenantId;
      const createdAt = record.created_at ?? new Date().toISOString();
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO waf_coverage_daily_rollups (
             id, tenant_id, rollup_date, total_assets, protected, underprotected, unprotected,
             unknown, excluded, coverage_ratio, created_at
           )
           VALUES ($1, $2, $3::date, $4, $5, $6, $7, $8, $9, $10, $11::timestamptz)
           ON CONFLICT (tenant_id, rollup_date)
           DO UPDATE SET
             total_assets = EXCLUDED.total_assets,
             protected = EXCLUDED.protected,
             underprotected = EXCLUDED.underprotected,
             unprotected = EXCLUDED.unprotected,
             unknown = EXCLUDED.unknown,
             excluded = EXCLUDED.excluded,
             coverage_ratio = EXCLUDED.coverage_ratio,
             created_at = EXCLUDED.created_at
           RETURNING ${WAF_COVERAGE_DAILY_ROLLUP_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.rollup_date,
            record.total_assets ?? 0,
            record.protected ?? 0,
            record.underprotected ?? 0,
            record.unprotected ?? 0,
            record.unknown ?? 0,
            record.excluded ?? 0,
            record.coverage_ratio ?? 0,
            createdAt,
          ],
        );
        return mapWafCoverageDailyRollupRow(rows[0]);
      });
    },

    async listWafCoverageDailyRollups(ctx, options = {}) {
      const tenantId = ctx.tenantId;
      const windowDays = Number(options.windowDays ?? options.window_days ?? 90);
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${WAF_COVERAGE_DAILY_ROLLUP_COLUMNS}
           FROM waf_coverage_daily_rollups
           WHERE tenant_id = $1
             AND rollup_date >= (CURRENT_DATE - ($2::int - 1))
           ORDER BY rollup_date ASC`,
          [tenantId, windowDays],
        );
        return rows.map(mapWafCoverageDailyRollupRow);
      });
    },
  };
}
