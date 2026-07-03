import { runWithTenantClient, withTenantContext } from './tenantContext.mjs';

const CVE_PIPELINE_ITEM_COLUMNS = `id, tenant_id, cve_id, published_at, severity, known_exploited,
  public_poc_signal, state, triage_summary_json, created_at, updated_at`;

const CVE_ASSET_MATCH_COLUMNS = `id, tenant_id, cve_pipeline_item_id, waf_asset_id, match_confidence,
  match_sources, validation_status, risk_score, finding_id, created_at, updated_at`;

const WAF_RULE_RECOMMENDATION_COLUMNS = `id, tenant_id, waf_asset_id, cve_asset_match_id, vendor,
  recommendation_type, recommendation_json, approval_status, ticket_id, created_at, updated_at`;

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function parseJsonObject(value) {
  if (value == null) return {};
  if (typeof value === 'string') {
    try {
      return JSON.parse(value);
    } catch {
      return {};
    }
  }
  return value;
}

function buildTriageSummaryJson(item = {}) {
  const existing = parseJsonObject(item.triage_summary_json);
  const summary = {
    affected_products: item.affected_products ?? existing.affected_products ?? [],
    vendor_advisories: item.vendor_advisories ?? existing.vendor_advisories ?? [],
    triage_result: item.triage_result ?? existing.triage_result ?? null,
  };
  const descriptionSummary = item.description_summary ?? existing.description_summary;
  if (typeof descriptionSummary === 'string' && descriptionSummary.trim()) {
    summary.description_summary = descriptionSummary.trim();
  }
  return summary;
}

export function mapCvePipelineItemRow(row) {
  if (!row) return null;
  const triageSummary = parseJsonObject(row.triage_summary_json);
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    cve_id: row.cve_id,
    published_at: row.published_at == null ? null : toIso(row.published_at),
    severity: row.severity ?? null,
    known_exploited: row.known_exploited === true,
    poc_indicator: row.public_poc_signal === true,
    public_poc_signal: row.public_poc_signal === true,
    affected_products: triageSummary.affected_products ?? [],
    vendor_advisories: triageSummary.vendor_advisories ?? [],
    triage_result: triageSummary.triage_result ?? null,
    stage: row.state ?? 'ingest',
    state: row.state ?? 'ingest',
    triage_summary_json: triageSummary,
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
  };
}

function decodeMatchSources(matchSources = []) {
  const sources = Array.isArray(matchSources) ? matchSources : [];
  const meta = {};
  const match_reasons = [];
  let match_source = null;

  for (const entry of sources) {
    const value = String(entry ?? '');
    if (value.startsWith('__meta:confidence_level:')) {
      meta.confidence_level = value.slice('__meta:confidence_level:'.length);
      continue;
    }
    if (value.startsWith('__meta:requires_review:')) {
      meta.requires_review = value.slice('__meta:requires_review:'.length) === 'true';
      continue;
    }
    if (value.startsWith('__meta:exposure_claim_allowed:')) {
      meta.exposure_claim_allowed = value.slice('__meta:exposure_claim_allowed:'.length) === 'true';
      continue;
    }
    if (value.startsWith('__meta:asset_display:')) {
      meta.asset_display = value.slice('__meta:asset_display:'.length);
      continue;
    }
    if (value.startsWith('__meta:last_waf_validation_run_id:')) {
      meta.last_waf_validation_run_id = value.slice('__meta:last_waf_validation_run_id:'.length);
      continue;
    }
    if (!match_source) {
      match_source = value;
      continue;
    }
    match_reasons.push(value);
  }

  return {
    match_source: match_source ?? 'keyword_guess',
    confidence_level: meta.confidence_level ?? 'low',
    requires_review: meta.requires_review ?? false,
    exposure_claim_allowed: meta.exposure_claim_allowed ?? false,
    asset_display: meta.asset_display ?? null,
    last_waf_validation_run_id: meta.last_waf_validation_run_id ?? null,
    match_reasons,
  };
}

function encodeMatchSources(match = {}) {
  const sources = [];
  if (match.match_source) {
    sources.push(String(match.match_source));
  }
  if (match.confidence_level) {
    sources.push(`__meta:confidence_level:${match.confidence_level}`);
  }
  sources.push(`__meta:requires_review:${match.requires_review === true}`);
  sources.push(`__meta:exposure_claim_allowed:${match.exposure_claim_allowed === true}`);
  if (match.asset_display) {
    sources.push(`__meta:asset_display:${match.asset_display}`);
  }
  if (match.last_waf_validation_run_id) {
    sources.push(`__meta:last_waf_validation_run_id:${match.last_waf_validation_run_id}`);
  }
  for (const reason of match.match_reasons ?? []) {
    const trimmed = String(reason).trim();
    if (trimmed) sources.push(trimmed);
  }
  return sources;
}

export function mapCveAssetMatchRow(row, assetDisplay = null) {
  if (!row) return null;
  const decoded = decodeMatchSources(row.match_sources);
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    cve_pipeline_item_id: row.cve_pipeline_item_id,
    waf_asset_id: row.waf_asset_id,
    asset_display: decoded.asset_display ?? assetDisplay,
    match_source: decoded.match_source,
    confidence_level: decoded.confidence_level,
    match_confidence: Number(row.match_confidence ?? 0),
    match_reasons: decoded.match_reasons,
    requires_review: decoded.requires_review,
    exposure_claim_allowed: decoded.exposure_claim_allowed,
    validation_status: row.validation_status ?? 'pending',
    last_waf_validation_run_id: decoded.last_waf_validation_run_id ?? null,
    risk_score: Number(row.risk_score ?? 0),
    finding_id: row.finding_id ?? null,
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
  };
}

export function mapWafRuleRecommendationRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    cve_asset_match_id: row.cve_asset_match_id ?? null,
    waf_asset_id: row.waf_asset_id,
    vendor: row.vendor,
    recommendation_type: row.recommendation_type,
    recommendation_json: parseJsonObject(row.recommendation_json),
    approval_status: row.approval_status ?? 'draft',
    ticket_id: row.ticket_id ?? null,
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
  };
}

export function createCvePipelineRepository(pool) {
  return {
    async listCvePipelineItems(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${CVE_PIPELINE_ITEM_COLUMNS}
           FROM cve_pipeline_items
           WHERE tenant_id = $1
           ORDER BY created_at ASC`,
          [tenantId],
        );
        return rows.map(mapCvePipelineItemRow);
      });
    },

    async getCvePipelineItem(ctx, id) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${CVE_PIPELINE_ITEM_COLUMNS}
           FROM cve_pipeline_items
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        return mapCvePipelineItemRow(rows[0] ?? null);
      });
    },

    async insertCvePipelineItem(ctx, item) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const triageSummary = buildTriageSummaryJson(item);
        const { rows } = await client.query(
          `INSERT INTO cve_pipeline_items (
             id, tenant_id, cve_id, published_at, severity, known_exploited, public_poc_signal,
             state, triage_summary_json, created_at, updated_at
           )
           VALUES ($1, $2, $3, $4::timestamptz, $5, $6, $7, $8, $9::jsonb, $10::timestamptz, $11::timestamptz)
           RETURNING ${CVE_PIPELINE_ITEM_COLUMNS}`,
          [
            item.id,
            tenantId,
            item.cve_id,
            item.published_at ?? null,
            item.severity ?? null,
            item.known_exploited === true,
            item.poc_indicator === true || item.public_poc_signal === true,
            item.stage ?? item.state ?? 'ingest',
            JSON.stringify(triageSummary),
            item.created_at,
            item.updated_at ?? item.created_at,
          ],
        );
        return mapCvePipelineItemRow(rows[0]);
      });
    },

    async saveMitigationPlaybook(ctx, id, playbook, options = {}) {
      const tenantId = ctx.tenantId;
      return runWithTenantClient(pool, tenantId, options.client, async (client) => {
        const existing = await client.query(
          `SELECT state, triage_summary_json
           FROM cve_pipeline_items
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        const row = existing.rows[0];
        if (!row) return null;

        const currentSummary = parseJsonObject(row.triage_summary_json);
        const triageSummary = {
          ...currentSummary,
          mitigation_playbook: playbook,
        };
        const updatedAt = playbook.updated_at ?? new Date().toISOString();
        const { rows } = await client.query(
          `UPDATE cve_pipeline_items
           SET triage_summary_json = $3::jsonb,
               updated_at = $4::timestamptz
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${CVE_PIPELINE_ITEM_COLUMNS}`,
          [tenantId, id, JSON.stringify(triageSummary), updatedAt],
        );
        return mapCvePipelineItemRow(rows[0] ?? null);
      });
    },

    async updateCvePipelineItemStage(ctx, id, stage, extras = {}, options = {}) {
      const tenantId = ctx.tenantId;
      return runWithTenantClient(pool, tenantId, options.client, async (client) => {
        const existing = await client.query(
          `SELECT triage_summary_json
           FROM cve_pipeline_items
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        const currentSummary = parseJsonObject(existing.rows[0]?.triage_summary_json);
        const triageSummary = {
          ...currentSummary,
          ...(extras.triage_result !== undefined ? { triage_result: extras.triage_result } : {}),
          ...(extras.affected_products !== undefined ? { affected_products: extras.affected_products } : {}),
          ...(extras.vendor_advisories !== undefined ? { vendor_advisories: extras.vendor_advisories } : {}),
          ...(extras.validation_bindings !== undefined
            ? {
                validation_bindings: {
                  ...(currentSummary.validation_bindings ?? {}),
                  ...extras.validation_bindings,
                },
              }
            : {}),
          ...(extras.mitigation_playbook !== undefined
            ? { mitigation_playbook: extras.mitigation_playbook }
            : {}),
        };
        const updatedAt = extras.updated_at ?? new Date().toISOString();
        const { rows } = await client.query(
          `UPDATE cve_pipeline_items
           SET state = $3,
               triage_summary_json = $4::jsonb,
               updated_at = $5::timestamptz
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${CVE_PIPELINE_ITEM_COLUMNS}`,
          [tenantId, id, stage, JSON.stringify(triageSummary), updatedAt],
        );
        return mapCvePipelineItemRow(rows[0] ?? null);
      });
    },

    async listCveAssetMatches(ctx, cveItemId) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${CVE_ASSET_MATCH_COLUMNS}
           FROM cve_asset_matches
           WHERE tenant_id = $1 AND cve_pipeline_item_id = $2
           ORDER BY created_at ASC`,
          [tenantId, cveItemId],
        );
        return rows.map((row) => mapCveAssetMatchRow(row));
      });
    },

    async getCveAssetMatch(ctx, id) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${CVE_ASSET_MATCH_COLUMNS}
           FROM cve_asset_matches
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        return mapCveAssetMatchRow(rows[0] ?? null);
      });
    },

    async updateCveAssetMatch(ctx, id, updates = {}, options = {}) {
      const tenantId = ctx.tenantId;
      return runWithTenantClient(pool, tenantId, options.client, async (client) => {
        const existing = await client.query(
          `SELECT ${CVE_ASSET_MATCH_COLUMNS}
           FROM cve_asset_matches
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        const current = mapCveAssetMatchRow(existing.rows[0] ?? null);
        if (!current) return null;

        const merged = {
          ...current,
          ...updates,
          match_sources: encodeMatchSources({
            ...current,
            ...updates,
          }),
        };
        const updatedAt = updates.updated_at ?? new Date().toISOString();
        const { rows } = await client.query(
          `UPDATE cve_asset_matches
           SET match_confidence = $3,
               match_sources = $4,
               validation_status = $5,
               risk_score = $6,
               finding_id = $7,
               updated_at = $8::timestamptz
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${CVE_ASSET_MATCH_COLUMNS}`,
          [
            tenantId,
            id,
            merged.match_confidence ?? current.match_confidence ?? 0,
            merged.match_sources,
            merged.validation_status ?? current.validation_status ?? 'pending',
            merged.risk_score ?? current.risk_score ?? 0,
            merged.finding_id ?? current.finding_id ?? null,
            updatedAt,
          ],
        );
        return mapCveAssetMatchRow(rows[0] ?? null);
      });
    },

    async insertCveAssetMatch(ctx, match) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO cve_asset_matches (
             id, tenant_id, cve_pipeline_item_id, waf_asset_id, match_confidence, match_sources,
             validation_status, risk_score, finding_id, created_at, updated_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::timestamptz, $11::timestamptz)
           ON CONFLICT (tenant_id, cve_pipeline_item_id, waf_asset_id) DO UPDATE
           SET match_confidence = EXCLUDED.match_confidence,
               match_sources = EXCLUDED.match_sources,
               validation_status = EXCLUDED.validation_status,
               risk_score = EXCLUDED.risk_score,
               updated_at = EXCLUDED.updated_at
           RETURNING ${CVE_ASSET_MATCH_COLUMNS}`,
          [
            match.id,
            tenantId,
            match.cve_pipeline_item_id,
            match.waf_asset_id,
            match.match_confidence ?? 0,
            encodeMatchSources(match),
            match.validation_status ?? 'pending',
            match.risk_score ?? 0,
            match.finding_id ?? null,
            match.created_at,
            match.updated_at ?? match.created_at,
          ],
        );
        return mapCveAssetMatchRow(rows[0]);
      });
    },

    async listWafRuleRecommendations(ctx, matchId) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${WAF_RULE_RECOMMENDATION_COLUMNS}
           FROM waf_rule_recommendations
           WHERE tenant_id = $1 AND cve_asset_match_id = $2
           ORDER BY created_at ASC`,
          [tenantId, matchId],
        );
        return rows.map(mapWafRuleRecommendationRow);
      });
    },

    async listWafRuleRecommendationsForPipelineItem(ctx, pipelineItemId, options = {}) {
      const tenantId = ctx.tenantId;
      return runWithTenantClient(pool, tenantId, options.client, async (client) => {
        const { rows } = await client.query(
          `SELECT ${WAF_RULE_RECOMMENDATION_COLUMNS}
           FROM waf_rule_recommendations rec
           INNER JOIN cve_asset_matches m
             ON m.tenant_id = rec.tenant_id
            AND m.id = rec.cve_asset_match_id
           WHERE rec.tenant_id = $1
             AND m.cve_pipeline_item_id = $2
           ORDER BY rec.created_at ASC`,
          [tenantId, pipelineItemId],
        );
        return rows.map(mapWafRuleRecommendationRow);
      });
    },

    async updateWafRuleRecommendation(ctx, id, updates = {}, options = {}) {
      const tenantId = ctx.tenantId;
      return runWithTenantClient(pool, tenantId, options.client, async (client) => {
        const existing = await client.query(
          `SELECT ${WAF_RULE_RECOMMENDATION_COLUMNS}
           FROM waf_rule_recommendations
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        const current = mapWafRuleRecommendationRow(existing.rows[0] ?? null);
        if (!current) return null;

        const updatedAt = updates.updated_at ?? new Date().toISOString();
        const { rows } = await client.query(
          `UPDATE waf_rule_recommendations
           SET approval_status = $3,
               ticket_id = $4,
               updated_at = $5::timestamptz
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${WAF_RULE_RECOMMENDATION_COLUMNS}`,
          [
            tenantId,
            id,
            updates.approval_status ?? current.approval_status,
            updates.ticket_id ?? current.ticket_id ?? null,
            updatedAt,
          ],
        );
        return mapWafRuleRecommendationRow(rows[0] ?? null);
      });
    },

    async insertWafRuleRecommendation(ctx, rec) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO waf_rule_recommendations (
             id, tenant_id, waf_asset_id, cve_asset_match_id, vendor, recommendation_type,
             recommendation_json, approval_status, ticket_id, created_at, updated_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10::timestamptz, $11::timestamptz)
           RETURNING ${WAF_RULE_RECOMMENDATION_COLUMNS}`,
          [
            rec.id,
            tenantId,
            rec.waf_asset_id,
            rec.cve_asset_match_id ?? null,
            rec.vendor,
            rec.recommendation_type,
            JSON.stringify(rec.recommendation_json ?? {}),
            rec.approval_status ?? 'draft',
            rec.ticket_id ?? null,
            rec.created_at,
            rec.updated_at ?? rec.created_at,
          ],
        );
        return mapWafRuleRecommendationRow(rows[0]);
      });
    },
  };
}