import { randomBytes } from 'node:crypto';
import { buildAuditRecord } from '../../audit.mjs';
import { encodeBase32 } from '../../lib/base32.mjs';
import { buildLoaCustodyDigest } from '../../lib/authorizationArtifactLedger.mjs';
import { decodeCursor, encodeCursor, paginateItems } from '../../lib/cursorPagination.mjs';
import { newId } from '../../lib/ids.mjs';
import { withTenantContext } from './tenantContext.mjs';

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function mapDnsRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    target_group_id: row.target_group_id,
    target_id: row.target_id,
    record_name: row.record_name,
    record_value: row.record_value,
    ttl_seconds: Number(row.ttl_seconds),
    state: row.state,
    issued_at: toIso(row.issued_at),
    expires_at: toIso(row.expires_at),
    resolved_at: row.resolved_at ? toIso(row.resolved_at) : null,
    last_checked_at: row.last_checked_at ? toIso(row.last_checked_at) : null,
    last_check_result: row.last_check_result ?? null,
    audit_entry_id: row.audit_entry_id,
  };
}

/** @type {readonly string[]} */
export const PORTAL_REVAMP_REPOSITORY_METHODS = Object.freeze([
  'listDnsChallengesByGroup',
  'insertDnsChallenge',
  'findDnsChallenge',
  'updateDnsChallenge',
  'resolveFqdnDomain',
  'getTargetVerificationCurrent',
  'listTargetVerifications',
  'insertTargetVerification',
  'getActiveLoaByGroup',
  'insertLoaSignature',
  'updateLoaSignature',
  'getFindingRemediationByFinding',
  'insertFindingRemediation',
  'updateFindingRemediation',
  'listSignupQueueEvents',
  'insertSignupQueueEvent',
  'getWafCoverageSummaryRow',
  'refreshWafCoverageSummary',
  'getTargetDetailBundle',
  'restoreTargetGroup',
  'getVerificationLadderCounts',
]);

/**
 * @param {import('pg').Pool} pool
 */
export function createPortalRevampRepository(pool) {
  return {
    async listDnsChallengesByGroup(ctx, groupId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT * FROM dns_challenges
           WHERE tenant_id = $1 AND target_group_id = $2
           ORDER BY issued_at DESC`,
          [ctx.tenantId, groupId],
        );
        return rows.map(mapDnsRow);
      });
    },

    async findDnsChallenge(ctx, id) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT * FROM dns_challenges WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        return mapDnsRow(rows[0] ?? null);
      });
    },

    async insertDnsChallenge(ctx, record, auditRepo) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const prior = await auditRepo.getLastAuditEntry(ctx.tenantId);
        const auditEntry = buildAuditRecord({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'dns_ownership.challenge_issued',
          resource_type: 'dns_challenge',
          resource_id: record.id,
        }, prior);
        await auditRepo.appendAuditEntry(auditEntry);
        const { rows } = await client.query(
          `INSERT INTO dns_challenges (
             id, tenant_id, target_group_id, target_id, record_name, record_value,
             ttl_seconds, state, issued_at, expires_at, audit_entry_id
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::timestamptz,$10::timestamptz,$11)
           RETURNING *`,
          [
            record.id,
            ctx.tenantId,
            record.target_group_id,
            record.target_id,
            record.record_name,
            record.record_value,
            record.ttl_seconds,
            record.state,
            record.issued_at,
            record.expires_at,
            auditEntry.id,
          ],
        );
        return mapDnsRow(rows[0]);
      });
    },

    async updateDnsChallenge(ctx, id, patch, auditRepo) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE dns_challenges
           SET state = COALESCE($3, state),
               resolved_at = COALESCE($4::timestamptz, resolved_at),
               last_checked_at = COALESCE($5::timestamptz, last_checked_at),
               last_check_result = COALESCE($6::jsonb, last_check_result),
               audit_entry_id = COALESCE($7, audit_entry_id)
           WHERE tenant_id = $1 AND id = $2
           RETURNING *`,
          [
            ctx.tenantId,
            id,
            patch.state ?? null,
            patch.resolved_at ?? null,
            patch.last_checked_at ?? null,
            patch.last_check_result ? JSON.stringify(patch.last_check_result) : null,
            patch.audit_entry_id ?? null,
          ],
        );
        return mapDnsRow(rows[0] ?? null);
      });
    },

    async resolveFqdnDomain(ctx, groupId, targetId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        if (targetId) {
          const { rows } = await client.query(
            `SELECT value FROM targets
             WHERE tenant_id = $1 AND target_group_id = $2 AND id = $3 AND kind = 'fqdn'
             LIMIT 1`,
            [ctx.tenantId, groupId, targetId],
          );
          return rows[0]?.value ? String(rows[0].value).trim().toLowerCase() : null;
        }
        const { rows } = await client.query(
          `SELECT value FROM targets
           WHERE tenant_id = $1 AND target_group_id = $2 AND kind = 'fqdn'
           ORDER BY created_at ASC LIMIT 1`,
          [ctx.tenantId, groupId],
        );
        return rows[0]?.value ? String(rows[0].value).trim().toLowerCase() : null;
      });
    },

    async getVerificationLadderCounts(ctx, groupId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows: targets } = await client.query(
          `SELECT id FROM targets WHERE tenant_id = $1 AND target_group_id = $2`,
          [ctx.tenantId, groupId],
        );
        const total = targets.length;
        const counts = { declared: total, dns_verified: 0, agent_verified: 0, user_confirmed: 0, total };
        if (!total) return counts;

        const { rows } = await client.query(
          `SELECT tvc.state, COUNT(*)::int AS count
           FROM targets t
           JOIN target_verification_current tvc
             ON tvc.target_id = t.id AND tvc.tenant_id = t.tenant_id
           WHERE t.tenant_id = $1 AND t.target_group_id = $2
           GROUP BY tvc.state`,
          [ctx.tenantId, groupId],
        );
        for (const row of rows) {
          if (row.state && counts[row.state] != null) counts[row.state] = Number(row.count);
        }
        return counts;
      });
    },

    async insertTargetVerification(ctx, record, auditRepo) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        let auditEntryId = record.audit_entry_id ?? null;
        if (auditRepo && !auditEntryId) {
          const prior = await auditRepo.getLastAuditEntry(ctx.tenantId);
          const auditEntry = buildAuditRecord({
            tenant_id: ctx.tenantId,
            actor_user_id: ctx.userId,
            actor_role: ctx.role,
            action: 'target_verification.transitioned',
            resource_type: 'target_verification',
            resource_id: record.id,
          }, prior);
          await auditRepo.appendAuditEntry(auditEntry);
          auditEntryId = auditEntry.id;
        }
        const { rows } = await client.query(
          `INSERT INTO target_verifications (
             id, tenant_id, target_id, state, source_kind, source_ref,
             transitioned_at, transitioned_by, audit_entry_id
           ) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::timestamptz,$8,$9)
           RETURNING *`,
          [
            record.id,
            ctx.tenantId,
            record.target_id,
            record.state,
            record.source_kind,
            JSON.stringify(record.source_ref ?? {}),
            record.transitioned_at,
            record.transitioned_by,
            auditEntryId,
          ],
        );
        return rows[0];
      });
    },

    async getActiveLoaByGroup(ctx, groupId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT * FROM loa_signatures
           WHERE tenant_id = $1 AND target_group_id = $2 AND state = 'signed'
           ORDER BY signed_at DESC LIMIT 1`,
          [ctx.tenantId, groupId],
        );
        const row = rows[0];
        if (!row) return null;
        return {
          ...row,
          signed_at: toIso(row.signed_at),
          expires_at: row.expires_at ? toIso(row.expires_at) : null,
        };
      });
    },

    async insertLoaSignature(ctx, record, auditRepo) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const prior = await auditRepo.getLastAuditEntry(ctx.tenantId);
        const auditEntry = buildAuditRecord({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'loa.signed',
          resource_type: 'loa_signature',
          resource_id: record.id,
        }, prior);
        await auditRepo.appendAuditEntry(auditEntry);
        const { rows } = await client.query(
          `INSERT INTO loa_signatures (
             id, tenant_id, target_group_id, state, signer_name, signer_title, signer_email,
             signed_at, expires_at, emergency_contact, attested, scope_snapshot,
             custody_artifact_id, custody_digest_sha256, audit_entry_id
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::timestamptz,$9::timestamptz,$10::jsonb,$11,$12::jsonb,$13,$14,$15)
           RETURNING *`,
          [
            record.id,
            ctx.tenantId,
            record.target_group_id,
            record.state,
            record.signer_name,
            record.signer_title,
            record.signer_email,
            record.signed_at,
            record.expires_at,
            JSON.stringify(record.emergency_contact ?? {}),
            record.attested,
            JSON.stringify(record.scope_snapshot ?? {}),
            record.custody_artifact_id,
            record.custody_digest_sha256,
            auditEntry.id,
          ],
        );
        return rows[0];
      });
    },

    async updateLoaSignature(ctx, loaId, patch, auditRepo) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        let auditEntryId = null;
        if (patch.state === 'revoked' && auditRepo) {
          const prior = await auditRepo.getLastAuditEntry(ctx.tenantId);
          const auditEntry = buildAuditRecord({
            tenant_id: ctx.tenantId,
            actor_user_id: ctx.userId,
            actor_role: ctx.role,
            action: 'loa.revoked',
            resource_type: 'loa_signature',
            resource_id: loaId,
          }, prior);
          await auditRepo.appendAuditEntry(auditEntry);
          auditEntryId = auditEntry.id;
        }
        const { rows } = await client.query(
          `UPDATE loa_signatures SET state = COALESCE($3, state)
           WHERE tenant_id = $1 AND id = $2 RETURNING *`,
          [ctx.tenantId, loaId, patch.state ?? null],
        );
        const row = rows[0] ?? null;
        if (!row) return null;
        return { ...row, signed_at: toIso(row.signed_at), audit_entry_id: auditEntryId ?? row.audit_entry_id };
      });
    },

    async getTargetDetailBundle(ctx, targetId, query = {}, options = {}) {
      const counter = options.queryCounter;
      const bump = () => { if (counter) counter.count += 1; };

      return withTenantContext(pool, ctx.tenantId, async (client) => {
        bump();
        const targetRes = await client.query(
          `SELECT * FROM targets WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, targetId],
        );
        const target = targetRes.rows[0];
        if (!target) return null;

        const targetMeta =
          target.metadata_json && typeof target.metadata_json === 'object'
            ? target.metadata_json
            : {};

        bump();
        const [verifications, loa, findings, runs, wafAsset, agentBinding, wafSnapshot] = await Promise.all([
          client.query(
            `SELECT * FROM target_verifications
             WHERE tenant_id = $1 AND target_id = $2 ORDER BY transitioned_at ASC`,
            [ctx.tenantId, targetId],
          ),
          client.query(
            `SELECT * FROM loa_signatures
             WHERE tenant_id = $1 AND target_group_id = $2 AND state = 'signed'
             ORDER BY signed_at DESC LIMIT 1`,
            [ctx.tenantId, target.target_group_id],
          ),
          client.query(
            `SELECT id, severity, title, status, created_at
             FROM findings WHERE tenant_id = $1 AND target_id = $2
             ORDER BY created_at DESC`,
            [ctx.tenantId, targetId],
          ),
          client.query(
            `SELECT id, check_id, status, started_at, created_at
             FROM test_runs WHERE tenant_id = $1 AND target_id = $2
             ORDER BY COALESCE(started_at, created_at) DESC LIMIT $3`,
            [ctx.tenantId, targetId, Number(query.runs_limit) || 5],
          ),
          client.query(
            `SELECT * FROM waf_assets WHERE tenant_id = $1 AND target_id = $2 LIMIT 1`,
            [ctx.tenantId, targetId],
          ),
          client.query(
            `SELECT id, created_at, metadata_json
             FROM agents
             WHERE tenant_id = $1 AND target_group_id = $2
               AND (
                 ($3::text IS NOT NULL AND $3 <> '' AND id = $3)
                 OR COALESCE(metadata_json->>'bound_target_id', '') = $4
               )
             ORDER BY created_at DESC LIMIT 1`,
            [
              ctx.tenantId,
              target.target_group_id,
              targetMeta.agent_id ?? null,
              targetId,
            ],
          ),
          client.query(
            `SELECT ps.status, ps.reason_codes, ps.created_at
             FROM waf_posture_snapshots ps
             JOIN waf_assets wa ON wa.id = ps.waf_asset_id AND wa.tenant_id = ps.tenant_id
             WHERE wa.tenant_id = $1 AND wa.target_id = $2 AND ps.is_current = TRUE
             ORDER BY ps.created_at DESC LIMIT 1`,
            [ctx.tenantId, targetId],
          ),
        ]);

        const wafConnector = wafAsset.rows[0]?.connector_id
          ? await client.query(
              `SELECT id, status, last_success_at, last_polled_at
               FROM waf_connectors WHERE tenant_id = $1 AND id = $2 LIMIT 1`,
              [ctx.tenantId, wafAsset.rows[0].connector_id],
            )
          : { rows: [] };

        const verificationRows = verifications.rows;
        const latest = verificationRows[verificationRows.length - 1];
        const findingsRows = findings.rows;
        const limit = Number(query.findings_limit);
        let findingsPage = findingsRows.map((f) => ({
          id: f.id,
          severity: f.severity,
          title: f.title,
          state: f.status,
          opened_at: toIso(f.created_at),
          owner_group: 'edge-sre',
        }));
        let findingsNextCursor = null;
        if (Number.isFinite(limit) && limit > 0) {
          const paged = paginateItems(findingsPage, { limit, cursor: query.findings_cursor, cursorField: 'id' });
          findingsPage = paged.items;
          findingsNextCursor = paged.next_cursor;
        } else {
          findingsPage = findingsPage.slice(0, 20);
        }

        const agentRow = agentBinding.rows[0] ?? null;
        const snapshotRow = wafSnapshot.rows[0] ?? null;
        const assetRow = wafAsset.rows[0] ?? null;
        const connectorRow = wafConnector.rows[0] ?? null;
        const runsRecent = runs.rows.map((run) => ({
          run_id: run.id,
          policy_id: run.check_id ?? null,
          verdict: run.status ?? 'unknown',
          started_at: toIso(run.started_at ?? run.created_at),
          agent_id: null,
        }));
        const wafPosture = assetRow
          ? {
              asset_id: assetRow.id,
              vendor: assetRow.vendor ?? 'generic',
              posture: snapshotRow?.status ?? assetRow.posture ?? 'unknown',
              drift_reason: Array.isArray(snapshotRow?.reason_codes) && snapshotRow.reason_codes.length
                ? snapshotRow.reason_codes[0]
                : null,
              validation: null,
              connector: connectorRow
                ? {
                    id: connectorRow.id,
                    state: connectorRow.status ?? 'unknown',
                    last_polled_at: toIso(connectorRow.last_success_at ?? connectorRow.last_polled_at),
                  }
                : null,
              fingerprint: null,
              marker_rules: assetRow.marker_rules ?? 0,
              origin_bypass: {
                state: assetRow.origin_bypass_state ?? 'not_exposed',
                last_checked_at: toIso(assetRow.origin_bypass_checked_at ?? snapshotRow?.created_at),
              },
              raw_context_yaml: `asset_id: ${assetRow.id}\nvendor: ${assetRow.vendor ?? 'generic'}\ntarget_id: ${targetId}\n`,
            }
          : null;

        const payload = {
          target: {
            id: target.id,
            tenant_id: target.tenant_id,
            target_group_id: target.target_group_id,
            kind: target.kind,
            value: target.value,
            expected_behavior: target.expected_behavior ?? 'cloud_baseline',
            agent_binding: agentRow
              ? {
                  agent_id: agentRow.id,
                  bound_at: toIso(agentRow.created_at),
                }
              : null,
            created_at: toIso(target.created_at),
            eligibility: latest?.state && latest.state !== 'unverified' ? 'eligible' : 'not_eligible',
            eligibility_reason: latest?.state && latest.state !== 'unverified' ? null : 'verification_required',
          },
          verification: {
            state: latest?.state ?? 'unverified',
            source_kind: latest?.source_kind ?? null,
            source_ref: latest?.source_ref ?? null,
            history: verificationRows.map((row) => ({
              state: row.state,
              transitioned_at: toIso(row.transitioned_at),
              ...(row.state !== 'pending' ? { source_ref: row.source_ref } : {}),
            })),
          },
          waf_posture: wafPosture,
          checks_applied: [],
          runs_recent: runsRecent,
          findings: findingsPage,
          findings_next_cursor: findingsNextCursor,
          loa: loa.rows[0]
            ? {
                id: loa.rows[0].id,
                state: loa.rows[0].state,
                signed_at: toIso(loa.rows[0].signed_at),
                signer_name: loa.rows[0].signer_name,
                custody_digest_sha256: loa.rows[0].custody_digest_sha256,
              }
            : null,
          counts: {
            runs_total: runs.rows.length,
            findings_open: findingsRows.filter((f) => f.status === 'open').length,
            findings_closed: findingsRows.filter((f) => f.status === 'closed' || f.status === 'accepted').length,
          },
        };
        payload.meta = {
          runs_empty_reason: runsRecent.length
            ? null
            : 'No bounded test runs have been recorded for this target yet.',
          findings_empty_reason: findingsPage.length
            ? null
            : 'No findings are scoped to this target yet.',
          checks_empty_reason: 'No checks are bound to this target group policy yet.',
          waf_empty_reason: wafPosture
            ? null
            : 'No WAF posture asset is linked to this target.',
        };
        return payload;
      });
    },

    async restoreTargetGroup(ctx, groupId, auditRepo) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE target_groups SET deleted_at = NULL, deleted_by = NULL
           WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NOT NULL
           RETURNING *`,
          [ctx.tenantId, groupId],
        );
        const restored = rows[0] ?? null;
        if (restored && auditRepo) {
          const prior = await auditRepo.getLastAuditEntry(ctx.tenantId);
          const auditEntry = buildAuditRecord({
            tenant_id: ctx.tenantId,
            actor_user_id: ctx.userId,
            actor_role: ctx.role,
            action: 'target_group.restored',
            resource_type: 'target_group',
            resource_id: groupId,
          }, prior);
          await auditRepo.appendAuditEntry(auditEntry);
        }
        return restored;
      });
    },

    async refreshWafCoverageSummary() {
      await pool.query('REFRESH MATERIALIZED VIEW CONCURRENTLY waf_coverage_summary');
    },

    async getWafCoverageSummaryRow(ctx) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT * FROM waf_coverage_summary WHERE tenant_id = $1`,
          [ctx.tenantId],
        );
        return rows[0] ?? null;
      });
    },

    async listSignupQueueEvents(requestId, options = {}) {
      const maxChars = Number(options.truncateMessageChars) || 500;
      const { rows } = await pool.query(
        `SELECT * FROM signup_queue_events WHERE request_id = $1 ORDER BY created_at ASC`,
        [requestId],
      );
      return rows.map((row) => ({
        ...row,
        created_at: toIso(row.created_at),
        message: row.message && String(row.message).length > maxChars
          ? String(row.message).slice(0, maxChars)
          : row.message,
      }));
    },

    async insertSignupQueueEvent(record) {
      const { rows } = await pool.query(
        `INSERT INTO signup_queue_events (id, tenant_id, request_id, event_kind, actor, message)
         VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
        [
          record.id,
          record.tenant_id ?? null,
          record.request_id,
          record.event_kind,
          record.actor,
          record.message ?? null,
        ],
      );
      return rows[0];
    },

    async getFindingRemediationByFinding(ctx, findingId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT * FROM finding_remediations WHERE tenant_id = $1 AND finding_id = $2`,
          [ctx.tenantId, findingId],
        );
        return rows[0] ?? null;
      });
    },

    async insertFindingRemediation(ctx, record) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO finding_remediations (
             id, tenant_id, finding_id, action_slug, owner_group, description, steps, audit_entry_id
           ) VALUES ($1,$2,$3,$4,$5,$6,$7::text[],$8) RETURNING *`,
          [
            record.id,
            ctx.tenantId,
            record.finding_id,
            record.action_slug,
            record.owner_group,
            record.description,
            record.steps ?? [],
            record.audit_entry_id,
          ],
        );
        return rows[0];
      });
    },

    async updateFindingRemediation(ctx, id, patch) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE finding_remediations
           SET state = COALESCE($3, state),
               delivered_at = COALESCE($4::timestamptz, delivered_at),
               delivered_via = COALESCE($5, delivered_via),
               delivered_ref = COALESCE($6, delivered_ref),
               updated_at = now()
           WHERE tenant_id = $1 AND id = $2 RETURNING *`,
          [
            ctx.tenantId,
            id,
            patch.state ?? null,
            patch.delivered_at ?? null,
            patch.delivered_via ?? null,
            patch.delivered_ref ?? null,
          ],
        );
        return rows[0] ?? null;
      });
    },

    async getTargetVerificationCurrent(ctx, targetId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT * FROM target_verification_current WHERE tenant_id = $1 AND target_id = $2`,
          [ctx.tenantId, targetId],
        );
        return rows[0] ?? null;
      });
    },

    async listTargetVerifications(ctx, targetId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT * FROM target_verifications
           WHERE tenant_id = $1 AND target_id = $2 ORDER BY transitioned_at ASC`,
          [ctx.tenantId, targetId],
        );
        return rows;
      });
    },
  };
}