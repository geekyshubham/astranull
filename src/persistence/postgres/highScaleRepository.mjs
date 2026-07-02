import { withTenantContext } from './tenantContext.mjs';
import { mergeRiskReviewOntoRequest } from '../../lib/highScalePolicy.mjs';

const HS_COLUMNS = `id, tenant_id, target_group_id, requested_by, state, reason, objective,
  requested_window, emergency_contacts, scope_confirmation, created_by, audit_trail, artifacts,
  scope_hash, soc_approvals, provider_approval_checklist, adapter_json, scheduled_window,
  provider_context_json, risk_review_json, created_at, updated_at`;

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function asObject(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  return {};
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function artifactFromRow(row) {
  const meta = asObject(row.metadata_json);
  const status = row.status === 'pending' ? 'pending_review' : row.status;
  return {
    id: row.id,
    type: row.type,
    status,
    provider_name: meta.provider_name ?? null,
    provider_ref: meta.provider_ref ?? null,
    valid_window: meta.valid_window ?? null,
    approved_targets: meta.approved_targets ?? [],
    approved_scenario_families: meta.approved_scenario_families ?? [],
    contact_path: meta.contact_path ?? null,
    approval_reference: meta.approval_reference ?? null,
    approver: meta.approver ?? null,
    max_rate: meta.max_rate ?? null,
    max_duration_minutes: meta.max_duration_minutes ?? null,
    emergency_contacts: meta.emergency_contacts ?? null,
    abort_criteria: meta.abort_criteria ?? null,
    retention_policy: meta.retention_policy ?? null,
    retained_artifact_metadata: meta.retained_artifact_metadata ?? null,
    uploader: meta.uploader ?? null,
    reference_uri_redacted: meta.reference_uri_redacted ?? row.reference_uri ?? 'metadata://redacted',
    created_at: toIso(row.created_at),
    reviewed_at: row.reviewed_at ? toIso(row.reviewed_at) : null,
    reviewed_by: row.reviewed_by ?? null,
    review_notes: meta.review_notes ?? null,
  };
}

function artifactToMetadata(artifact) {
  return {
    provider_name: artifact.provider_name,
    provider_ref: artifact.provider_ref,
    valid_window: artifact.valid_window,
    approved_targets: artifact.approved_targets,
    approved_scenario_families: artifact.approved_scenario_families,
    contact_path: artifact.contact_path,
    approval_reference: artifact.approval_reference,
    approver: artifact.approver,
    max_rate: artifact.max_rate,
    max_duration_minutes: artifact.max_duration_minutes,
    emergency_contacts: artifact.emergency_contacts,
    abort_criteria: artifact.abort_criteria,
    retention_policy: artifact.retention_policy,
    retained_artifact_metadata: artifact.retained_artifact_metadata,
    uploader: artifact.uploader,
    reference_uri_redacted: artifact.reference_uri_redacted,
    review_notes: artifact.review_notes,
  };
}

function mapRequestRow(row) {
  if (!row) return null;
  const riskReview = asObject(row.risk_review_json);
  const mapped = {
    id: row.id,
    tenant_id: row.tenant_id,
    target_group_id: row.target_group_id,
    reason: row.reason,
    objective: row.objective,
    requested_window: asObject(row.requested_window),
    emergency_contacts: asArray(row.emergency_contacts),
    scope_confirmation: Boolean(row.scope_confirmation),
    created_by: row.created_by,
    created_at: toIso(row.created_at),
    updated_at: row.updated_at ? toIso(row.updated_at) : null,
    state: row.state,
    audit_trail: asArray(row.audit_trail),
    artifacts: asArray(row.artifacts),
    scope_hash: row.scope_hash,
    soc_approvals: asArray(row.soc_approvals),
    provider_approval_checklist: asArray(row.provider_approval_checklist),
    adapter: asObject(row.adapter_json),
    scheduled_window: row.scheduled_window ?? null,
    provider_context: asObject(row.provider_context_json),
  };
  return mergeRiskReviewOntoRequest(mapped, riskReview);
}

function mapTelemetryRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    high_scale_request_id: row.high_scale_request_id,
    category: row.category,
    live_status: row.live_status,
    observed_at: toIso(row.observed_at),
    source: row.source,
    metrics: asObject(row.metrics_json),
    created_at: toIso(row.created_at),
    recorded_by: row.recorded_by,
  };
}

function mapSocReportRow(row) {
  if (!row) return null;
  const derived = asObject(row.derived_json);
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    high_scale_request_id: row.high_scale_request_id,
    created_at: toIso(row.created_at),
    created_by: row.created_by,
    updated_at: toIso(row.updated_at),
    updated_by: row.updated_by,
    impact_summary: row.impact_summary ?? '',
    recommendations: row.recommendations ?? '',
    customer_summary: row.customer_summary ?? '',
    residual_risk: row.residual_risk ?? '',
    next_steps: row.next_steps ?? '',
    attachments: asArray(row.attachments_json),
    evidence_ids: Array.isArray(row.evidence_ids) ? row.evidence_ids : [],
    timeline: derived.timeline ?? [],
    artifacts: derived.artifacts ?? [],
    soc_notes: derived.soc_notes ?? [],
    adapter: derived.adapter ?? {},
    telemetry_summary: derived.telemetry_summary ?? {},
    final_state: row.final_state ?? derived.final_state ?? null,
  };
}

/**
 * @param {import('pg').Pool} pool
 */
export function createHighScaleRepository(pool) {
  return {
    async createHighScaleRequest(ctx, record) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const riskReview = {
          ...(record.risk_review_json ?? {}),
          authorization_pack_status: record.authorization_pack_status ?? null,
        };
        const { rows } = await client.query(
          `INSERT INTO high_scale_requests (
             id, tenant_id, target_group_id, state, reason, objective, requested_window,
             emergency_contacts, scope_confirmation, created_by, audit_trail, artifacts,
             scope_hash, soc_approvals, provider_approval_checklist, adapter_json,
             scheduled_window, provider_context_json, risk_review_json, created_at
           )
           VALUES (
             $1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10, $11::jsonb, $12::jsonb,
             $13, $14::jsonb, $15::jsonb, $16::jsonb, $17::jsonb, $18::jsonb, $19::jsonb, $20::timestamptz
           )
           RETURNING ${HS_COLUMNS}`,
          [
            record.id,
            ctx.tenantId,
            record.target_group_id,
            record.state,
            record.reason,
            record.objective,
            JSON.stringify(record.requested_window ?? {}),
            JSON.stringify(record.emergency_contacts ?? []),
            record.scope_confirmation === true,
            record.created_by,
            JSON.stringify(record.audit_trail ?? []),
            JSON.stringify(record.artifacts ?? []),
            record.scope_hash,
            JSON.stringify(record.soc_approvals ?? []),
            JSON.stringify(record.provider_approval_checklist ?? []),
            JSON.stringify(record.adapter ?? {}),
            record.scheduled_window ? JSON.stringify(record.scheduled_window) : null,
            JSON.stringify(record.provider_context ?? {}),
            JSON.stringify(riskReview),
            record.created_at,
          ],
        );
        return mapRequestRow(rows[0]);
      });
    },

    async listHighScaleRequests(ctx) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${HS_COLUMNS}
           FROM high_scale_requests
           WHERE tenant_id = $1
           ORDER BY created_at DESC`,
          [ctx.tenantId],
        );
        return rows.map(mapRequestRow);
      });
    },

    async getHighScaleRequest(ctx, id) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${HS_COLUMNS}
           FROM high_scale_requests
           WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        return mapRequestRow(rows[0] ?? null);
      });
    },

    async updateHighScaleRequest(ctx, id, patch) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const sets = [];
        const params = [];
        let n = 1;

        const assignJson = (col, val) => {
          sets.push(`${col} = $${n}::jsonb`);
          params.push(JSON.stringify(val ?? (col.includes('artifacts') ? [] : {})));
          n += 1;
        };

        if (patch.state !== undefined) {
          sets.push(`state = $${n}`);
          params.push(patch.state);
          n += 1;
        }
        if (patch.audit_trail !== undefined) assignJson('audit_trail', patch.audit_trail);
        if (patch.artifacts !== undefined) assignJson('artifacts', patch.artifacts);
        if (patch.scope_hash !== undefined) {
          sets.push(`scope_hash = $${n}`);
          params.push(patch.scope_hash);
          n += 1;
        }
        if (patch.soc_approvals !== undefined) assignJson('soc_approvals', patch.soc_approvals);
        if (patch.provider_approval_checklist !== undefined) {
          assignJson('provider_approval_checklist', patch.provider_approval_checklist);
        }
        if (patch.adapter !== undefined) assignJson('adapter_json', patch.adapter);
        if (patch.scheduled_window !== undefined) {
          sets.push(`scheduled_window = $${n}::jsonb`);
          params.push(patch.scheduled_window ? JSON.stringify(patch.scheduled_window) : null);
          n += 1;
        }
        if (patch.risk_review_json !== undefined) assignJson('risk_review_json', patch.risk_review_json);
        if (patch.authorization_pack_status !== undefined) {
          const existing = await client.query(
            `SELECT risk_review_json FROM high_scale_requests WHERE tenant_id = $1 AND id = $2`,
            [ctx.tenantId, id],
          );
          const risk = asObject(existing.rows[0]?.risk_review_json);
          risk.authorization_pack_status = patch.authorization_pack_status;
          assignJson('risk_review_json', risk);
        }

        sets.push(`updated_at = $${n}::timestamptz`);
        params.push(patch.updated_at ?? new Date().toISOString());
        n += 1;

        params.push(ctx.tenantId, id);
        const { rows } = await client.query(
          `UPDATE high_scale_requests
           SET ${sets.join(', ')}
           WHERE tenant_id = $${n} AND id = $${n + 1}
           RETURNING ${HS_COLUMNS}`,
          params,
        );
        return mapRequestRow(rows[0] ?? null);
      });
    },

    async listRunningHighScaleRequests(ctx) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${HS_COLUMNS}
           FROM high_scale_requests
           WHERE tenant_id = $1 AND state = 'running'`,
          [ctx.tenantId],
        );
        return rows.map(mapRequestRow);
      });
    },

    async insertAuthorizationArtifact(ctx, requestId, artifact) {
      const dbStatus = artifact.status === 'pending_review' ? 'pending' : artifact.status;
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO authorization_artifacts (
             id, tenant_id, high_scale_request_id, type, reference_uri, status,
             reviewed_by, reviewed_at, metadata_json, created_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8::timestamptz, $9::jsonb, $10::timestamptz)
           RETURNING id, tenant_id, high_scale_request_id, type, reference_uri, status,
                     reviewed_by, reviewed_at, metadata_json, created_at`,
          [
            artifact.id,
            ctx.tenantId,
            requestId,
            artifact.type,
            artifact.reference_uri_redacted ?? 'metadata://redacted',
            dbStatus,
            artifact.reviewed_by ?? null,
            artifact.reviewed_at ?? null,
            JSON.stringify(artifactToMetadata(artifact)),
            artifact.created_at,
          ],
        );
        return artifactFromRow(rows[0]);
      });
    },

    async updateAuthorizationArtifact(ctx, requestId, artifactId, patch) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const existing = await client.query(
          `SELECT id, tenant_id, high_scale_request_id, type, reference_uri, status,
                  reviewed_by, reviewed_at, metadata_json, created_at
           FROM authorization_artifacts
           WHERE tenant_id = $1 AND high_scale_request_id = $2 AND id = $3`,
          [ctx.tenantId, requestId, artifactId],
        );
        if (!existing.rows[0]) return null;
        const row = existing.rows[0];
        const meta = { ...asObject(row.metadata_json), ...(patch.metadata ?? {}) };
        const status = patch.status != null ? (patch.status === 'pending_review' ? 'pending' : patch.status) : row.status;
        const { rows } = await client.query(
          `UPDATE authorization_artifacts
           SET status = $1, reviewed_by = $2, reviewed_at = $3::timestamptz, metadata_json = $4::jsonb
           WHERE tenant_id = $5 AND id = $6
           RETURNING id, tenant_id, high_scale_request_id, type, reference_uri, status,
                     reviewed_by, reviewed_at, metadata_json, created_at`,
          [
            status,
            patch.reviewed_by ?? row.reviewed_by,
            patch.reviewed_at ?? row.reviewed_at,
            JSON.stringify(meta),
            ctx.tenantId,
            artifactId,
          ],
        );
        return artifactFromRow(rows[0]);
      });
    },

    async listAuthorizationArtifacts(ctx, requestId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, high_scale_request_id, type, reference_uri, status,
                  reviewed_by, reviewed_at, metadata_json, created_at
           FROM authorization_artifacts
           WHERE tenant_id = $1 AND high_scale_request_id = $2
           ORDER BY created_at`,
          [ctx.tenantId, requestId],
        );
        return rows.map(artifactFromRow);
      });
    },

    async appendSocNote(ctx, requestId, note) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO soc_notes (id, tenant_id, high_scale_request_id, body, created_by, created_at)
           VALUES ($1, $2, $3, $4, $5, $6::timestamptz)
           RETURNING id, tenant_id, high_scale_request_id, body, created_by, created_at`,
          [note.id, ctx.tenantId, requestId, note.body, note.author ?? note.created_by, note.created_at],
        );
        const row = rows[0];
        return {
          id: row.id,
          tenant_id: row.tenant_id,
          high_scale_request_id: row.high_scale_request_id,
          body: row.body,
          author: row.created_by,
          created_at: toIso(row.created_at),
        };
      });
    },

    async listSocNotes(ctx, requestId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, high_scale_request_id, body, created_by, created_at
           FROM soc_notes
           WHERE tenant_id = $1 AND high_scale_request_id = $2
           ORDER BY created_at`,
          [ctx.tenantId, requestId],
        );
        return rows.map((row) => ({
          id: row.id,
          tenant_id: row.tenant_id,
          high_scale_request_id: row.high_scale_request_id,
          body: row.body,
          author: row.created_by,
          created_at: toIso(row.created_at),
        }));
      });
    },

    async appendTelemetry(ctx, record) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO high_scale_telemetry (
             id, tenant_id, high_scale_request_id, category, live_status, observed_at,
             source, metrics_json, created_at, recorded_by
           )
           VALUES ($1, $2, $3, $4, $5, $6::timestamptz, $7, $8::jsonb, $9::timestamptz, $10)
           RETURNING id, tenant_id, high_scale_request_id, category, live_status, observed_at,
                     source, metrics_json, created_at, recorded_by`,
          [
            record.id,
            ctx.tenantId,
            record.high_scale_request_id,
            record.category,
            record.live_status,
            record.observed_at,
            record.source,
            JSON.stringify(record.metrics ?? {}),
            record.created_at,
            record.recorded_by,
          ],
        );
        return mapTelemetryRow(rows[0]);
      });
    },

    async listTelemetry(ctx, requestId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, high_scale_request_id, category, live_status, observed_at,
                  source, metrics_json, created_at, recorded_by
           FROM high_scale_telemetry
           WHERE tenant_id = $1 AND high_scale_request_id = $2
           ORDER BY observed_at DESC`,
          [ctx.tenantId, requestId],
        );
        return rows.map(mapTelemetryRow);
      });
    },

    async getSocReport(ctx, requestId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, high_scale_request_id, created_at, created_by, updated_at, updated_by,
                  impact_summary, recommendations, customer_summary, residual_risk, next_steps,
                  attachments_json, evidence_ids, derived_json, final_state
           FROM soc_reports
           WHERE tenant_id = $1 AND high_scale_request_id = $2`,
          [ctx.tenantId, requestId],
        );
        return mapSocReportRow(rows[0] ?? null);
      });
    },

    async upsertSocReport(ctx, requestId, report) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const derived = {
          timeline: report.timeline ?? [],
          artifacts: report.artifacts ?? [],
          soc_notes: report.soc_notes ?? [],
          adapter: report.adapter ?? {},
          telemetry_summary: report.telemetry_summary ?? {},
          final_state: report.final_state,
        };
        const { rows } = await client.query(
          `INSERT INTO soc_reports (
             id, tenant_id, high_scale_request_id, created_at, created_by, updated_at, updated_by,
             impact_summary, recommendations, customer_summary, residual_risk, next_steps,
             attachments_json, evidence_ids, derived_json, final_state
           )
           VALUES (
             $1, $2, $3, $4::timestamptz, $5, $6::timestamptz, $7,
             $8, $9, $10, $11, $12, $13::jsonb, $14, $15::jsonb, $16
           )
           ON CONFLICT (tenant_id, high_scale_request_id)
           DO UPDATE SET
             updated_at = EXCLUDED.updated_at,
             updated_by = EXCLUDED.updated_by,
             impact_summary = EXCLUDED.impact_summary,
             recommendations = EXCLUDED.recommendations,
             customer_summary = EXCLUDED.customer_summary,
             residual_risk = EXCLUDED.residual_risk,
             next_steps = EXCLUDED.next_steps,
             attachments_json = EXCLUDED.attachments_json,
             evidence_ids = EXCLUDED.evidence_ids,
             derived_json = EXCLUDED.derived_json,
             final_state = EXCLUDED.final_state
           RETURNING id, tenant_id, high_scale_request_id, created_at, created_by, updated_at, updated_by,
                     impact_summary, recommendations, customer_summary, residual_risk, next_steps,
                     attachments_json, evidence_ids, derived_json, final_state`,
          [
            report.id,
            ctx.tenantId,
            requestId,
            report.created_at,
            report.created_by,
            report.updated_at,
            report.updated_by,
            report.impact_summary ?? '',
            report.recommendations ?? '',
            report.customer_summary ?? '',
            report.residual_risk ?? '',
            report.next_steps ?? '',
            JSON.stringify(report.attachments ?? []),
            report.evidence_ids ?? [],
            JSON.stringify(derived),
            report.final_state,
          ],
        );
        return mapSocReportRow(rows[0]);
      });
    },
  };
}

export { mapRequestRow, artifactFromRow, mapTelemetryRow, mapSocReportRow };