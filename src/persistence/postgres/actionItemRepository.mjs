import { withTenantContext } from './tenantContext.mjs';

const ACTION_ITEM_COLUMNS = `id, tenant_id, category, title, asset_display, waf_asset_id, owner, severity,
  evidence_json, recommended_solution, retest_url, status, primary_reason, cve_pipeline_item_id,
  created_at, updated_at`;

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

function buildEvidenceJson(item = {}) {
  const existing = parseJsonObject(item.evidence_json);
  const evidence = item.evidence ?? existing;
  return {
    ...existing,
    summary: evidence.summary ?? existing.summary ?? null,
    links: evidence.links ?? existing.links ?? [],
    asset: item.asset ?? existing.asset ?? null,
    finding_ids: item.finding_ids ?? existing.finding_ids ?? [],
    dedupe_key: item.dedupe_key ?? existing.dedupe_key ?? null,
  };
}

function deriveWafAssetId(item, evidenceJson) {
  if (typeof item.waf_asset_id === 'string' && item.waf_asset_id.trim()) {
    return item.waf_asset_id.trim();
  }
  if (typeof item.asset?.id === 'string' && item.asset.id.trim()) {
    return item.asset.id.trim();
  }
  if (typeof evidenceJson.asset?.id === 'string' && evidenceJson.asset.id.trim()) {
    return evidenceJson.asset.id.trim();
  }
  const dedupeKey = item.dedupe_key ?? evidenceJson.dedupe_key;
  if (typeof dedupeKey === 'string' && dedupeKey.includes(':')) {
    return dedupeKey.split(':')[0];
  }
  return null;
}

export function mapActionItemRow(row) {
  if (!row) return null;
  const evidenceJson = parseJsonObject(row.evidence_json);
  const wafAssetId = row.waf_asset_id ?? evidenceJson.asset?.id ?? null;
  return {
    action_item_id: row.id,
    id: row.id,
    tenant_id: row.tenant_id,
    category: row.category,
    title: row.title,
    asset: evidenceJson.asset ?? {
      id: wafAssetId,
      display: row.asset_display ?? 'declared asset',
    },
    asset_display: row.asset_display ?? null,
    waf_asset_id: wafAssetId,
    owner: row.owner ?? 'security-operations',
    severity: row.severity ?? 'medium',
    evidence: {
      summary: evidenceJson.summary ?? '',
      links: evidenceJson.links ?? [],
    },
    evidence_json: evidenceJson,
    recommended_solution: row.recommended_solution ?? null,
    retest_url: row.retest_url ?? null,
    status: row.status ?? 'open',
    primary_reason: row.primary_reason ?? null,
    finding_ids: evidenceJson.finding_ids ?? [],
    dedupe_key: evidenceJson.dedupe_key ?? null,
    cve_pipeline_item_id: row.cve_pipeline_item_id ?? null,
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
  };
}

export function createActionItemRepository(pool) {
  return {
    async listActionItems(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${ACTION_ITEM_COLUMNS}
           FROM waf_action_items
           WHERE tenant_id = $1
           ORDER BY created_at ASC`,
          [tenantId],
        );
        return rows.map(mapActionItemRow);
      });
    },

    async getActionItem(ctx, id) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${ACTION_ITEM_COLUMNS}
           FROM waf_action_items
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        return mapActionItemRow(rows[0] ?? null);
      });
    },

    async findOpenActionItemByDedupe(ctx, wafAssetId, primaryReason) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${ACTION_ITEM_COLUMNS}
           FROM waf_action_items
           WHERE tenant_id = $1
             AND waf_asset_id = $2
             AND primary_reason = $3
             AND status NOT IN ('resolved', 'accepted_risk')
           LIMIT 1`,
          [tenantId, wafAssetId, primaryReason],
        );
        return mapActionItemRow(rows[0] ?? null);
      });
    },

    async insertActionItem(ctx, item) {
      const tenantId = ctx.tenantId;
      const evidenceJson = buildEvidenceJson(item);
      const assetDisplay = item.asset_display
        ?? item.asset?.display
        ?? null;
      const primaryReason = item.primary_reason
        ?? item.dedupe_key?.split(':').slice(1).join(':')
        ?? 'waf_coverage';
      const wafAssetId = deriveWafAssetId(item, evidenceJson);

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO waf_action_items (
             id, tenant_id, category, title, asset_display, waf_asset_id, owner, severity, evidence_json,
             recommended_solution, retest_url, status, primary_reason, cve_pipeline_item_id,
             created_at, updated_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12, $13, $14, $15::timestamptz, $16::timestamptz)
           ON CONFLICT (tenant_id, waf_asset_id, primary_reason) DO UPDATE
           SET title = EXCLUDED.title,
               owner = EXCLUDED.owner,
               severity = EXCLUDED.severity,
               evidence_json = EXCLUDED.evidence_json,
               recommended_solution = EXCLUDED.recommended_solution,
               retest_url = EXCLUDED.retest_url,
               status = EXCLUDED.status,
               updated_at = EXCLUDED.updated_at
           RETURNING ${ACTION_ITEM_COLUMNS}`,
          [
            item.action_item_id ?? item.id,
            tenantId,
            item.category,
            item.title,
            assetDisplay,
            wafAssetId,
            item.owner ?? 'security-operations',
            item.severity ?? 'medium',
            JSON.stringify(evidenceJson),
            item.recommended_solution ?? null,
            item.retest_url ?? null,
            item.status ?? 'open',
            primaryReason,
            item.cve_pipeline_item_id ?? null,
            item.created_at,
            item.updated_at ?? item.created_at,
          ],
        );
        return mapActionItemRow(rows[0]);
      });
    },

    async updateActionItemStatus(ctx, id, status, extras = {}) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows: existingRows } = await client.query(
          `SELECT evidence_json
           FROM waf_action_items
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        const existing = existingRows[0];
        if (!existing) return null;

        const evidenceJson = parseJsonObject(existing.evidence_json);
        const { rows } = await client.query(
          `UPDATE waf_action_items
           SET status = $3,
               evidence_json = $4::jsonb,
               updated_at = $5::timestamptz
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${ACTION_ITEM_COLUMNS}`,
          [
            tenantId,
            id,
            status,
            JSON.stringify(evidenceJson),
            extras.updated_at ?? new Date().toISOString(),
          ],
        );
        return mapActionItemRow(rows[0] ?? null);
      });
    },
  };
}