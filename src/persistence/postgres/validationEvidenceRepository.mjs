import { withTenantContext } from './tenantContext.mjs';

const TEST_RUN_COLUMNS = `id, tenant_id, target_group_id, target_id, check_id, created_by, initiated_by,
  risk_class, safety_class, vector_family, status, probe_external_result, awaiting_external_probe,
  remediation_template, safety_constraints, correlation_json, collection_deadline_at, started_at,
  completed_at, summary_json, created_at`;

const EVENT_COLUMNS = `id, tenant_id, event_id, test_run_id, target_id, check_id, agent_id, source,
  signal_type, nonce_hash, timestamp, metadata_json`;

const EVIDENCE_COLUMNS = `id, tenant_id, test_run_id, label, metadata_json, related_event_id, created_at`;

const VERDICT_COLUMNS = `id, tenant_id, test_run_id, target_id, check_id, verdict, confidence,
  explanation, evidence_ids, placement_confidence_json, created_at`;

const FINDING_COLUMNS = `id, tenant_id, target_group_id, target_id, test_run_id, check_id, title, severity,
  status, evidence_ids, notes, remediation_template, verdict_id, last_verdict_id, assignee,
  created_at, updated_at`;

const DEFAULT_TEST_RUN_LIST_LIMIT = 100;
const MAX_TEST_RUN_LIST_LIMIT = 500;
const DEFAULT_RUN_EVENTS_LIST_LIMIT = 200;
const MAX_RUN_EVENTS_LIST_LIMIT = 1000;
const DEFAULT_EVIDENCE_LIST_LIMIT = 100;
const MAX_EVIDENCE_LIST_LIMIT = 500;

function normalizeBoundedLimit(limit, defaultLimit, maxLimit) {
  if (limit === undefined || limit === null) {
    return defaultLimit;
  }
  const n = Number(limit);
  if (!Number.isFinite(n) || n < 1) {
    return defaultLimit;
  }
  return Math.min(Math.floor(n), maxLimit);
}

function normalizeTestRunListLimit(limit) {
  return normalizeBoundedLimit(limit, DEFAULT_TEST_RUN_LIST_LIMIT, MAX_TEST_RUN_LIST_LIMIT);
}

function normalizeRunEventsListLimit(limit) {
  return normalizeBoundedLimit(limit, DEFAULT_RUN_EVENTS_LIST_LIMIT, MAX_RUN_EVENTS_LIST_LIMIT);
}

function normalizeEvidenceListLimit(limit) {
  return normalizeBoundedLimit(limit, DEFAULT_EVIDENCE_LIST_LIMIT, MAX_EVIDENCE_LIST_LIMIT);
}

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function asStringArray(value) {
  return Array.isArray(value) ? value : [];
}

function asObject(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  return {};
}

function mapTestRunRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    target_group_id: row.target_group_id,
    target_id: row.target_id ?? undefined,
    check_id: row.check_id,
    created_by: row.created_by ?? undefined,
    initiated_by: row.initiated_by ?? undefined,
    risk_class: row.risk_class ?? undefined,
    safety_class: row.safety_class ?? undefined,
    vector_family: row.vector_family ?? undefined,
    status: row.status,
    probe_external_result: row.probe_external_result ?? undefined,
    awaiting_external_probe: Boolean(row.awaiting_external_probe),
    remediation_template: row.remediation_template ?? undefined,
    safety_constraints: asObject(row.safety_constraints),
    correlation: asObject(row.correlation_json),
    collection_deadline_at:
      row.collection_deadline_at == null ? null : toIso(row.collection_deadline_at),
    started_at: row.started_at == null ? null : toIso(row.started_at),
    completed_at: row.completed_at == null ? null : toIso(row.completed_at),
    summary: asObject(row.summary_json),
    created_at: toIso(row.created_at),
  };
}

function mapEventRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    event_id: row.event_id ?? undefined,
    test_run_id: row.test_run_id ?? undefined,
    target_id: row.target_id ?? undefined,
    check_id: row.check_id ?? undefined,
    agent_id: row.agent_id ?? undefined,
    source: row.source ?? undefined,
    signal_type: row.signal_type ?? undefined,
    nonce_hash: row.nonce_hash ?? undefined,
    timestamp: toIso(row.timestamp),
    metadata: asObject(row.metadata_json),
  };
}

function mapEvidenceRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    test_run_id: row.test_run_id ?? undefined,
    label: row.label ?? undefined,
    metadata: asObject(row.metadata_json),
    related_event_id: row.related_event_id ?? null,
    created_at: toIso(row.created_at),
  };
}

function mapVerdictRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    test_run_id: row.test_run_id,
    target_id: row.target_id ?? undefined,
    check_id: row.check_id ?? undefined,
    verdict: row.verdict,
    confidence: row.confidence ?? undefined,
    explanation: row.explanation ?? undefined,
    evidence_ids: asStringArray(row.evidence_ids),
    placement_confidence: asObject(row.placement_confidence_json),
    created_at: toIso(row.created_at),
  };
}

function placementConfidenceJson(record) {
  return JSON.stringify(asObject(record.placement_confidence));
}

function mapFindingRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    target_group_id: row.target_group_id ?? undefined,
    target_id: row.target_id ?? undefined,
    test_run_id: row.test_run_id ?? undefined,
    check_id: row.check_id ?? undefined,
    title: row.title,
    severity: row.severity,
    status: row.status,
    evidence_ids: asStringArray(row.evidence_ids),
    notes: row.notes ?? undefined,
    remediation_template: row.remediation_template ?? undefined,
    verdict_id: row.verdict_id ?? undefined,
    last_verdict_id: row.last_verdict_id ?? undefined,
    assignee: row.assignee ?? null,
    created_at: toIso(row.created_at),
    updated_at: row.updated_at == null ? null : toIso(row.updated_at),
  };
}

/**
 * @param {import('pg').Pool} pool
 */
export function createValidationEvidenceRepository(pool) {
  async function queryEvidenceList(client, tenantId, options = {}) {
    const boundedLimit = normalizeEvidenceListLimit(options.limit);
    const params = [tenantId];
    const conditions = ['tenant_id = $1'];
    let paramIndex = 2;

    if (options.testRunId != null && options.testRunId !== '') {
      conditions.push(`test_run_id = $${paramIndex}`);
      params.push(options.testRunId);
      paramIndex += 1;
    }
    if (options.beforeCreatedAt != null) {
      conditions.push(`created_at < $${paramIndex}::timestamptz`);
      params.push(options.beforeCreatedAt);
      paramIndex += 1;
    }

    params.push(boundedLimit);
    const limitParam = paramIndex;

    const { rows } = await client.query(
      `SELECT ${EVIDENCE_COLUMNS}
       FROM evidence_vault
       WHERE ${conditions.join(' AND ')}
       ORDER BY created_at DESC
       LIMIT $${limitParam}`,
      params,
    );
    return rows;
  }

  return {
    async listTestRuns(ctx, options = {}) {
      const boundedLimit = normalizeTestRunListLimit(options.limit);
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const params = [ctx.tenantId];
        const conditions = ['tenant_id = $1'];
        let paramIndex = 2;

        if (options.targetGroupId != null && options.targetGroupId !== '') {
          conditions.push(`target_group_id = $${paramIndex}`);
          params.push(options.targetGroupId);
          paramIndex += 1;
        }
        if (Array.isArray(options.statuses) && options.statuses.length > 0) {
          conditions.push(`status = ANY($${paramIndex})`);
          params.push(options.statuses);
          paramIndex += 1;
        }
        if (options.beforeCreatedAt != null) {
          conditions.push(`created_at < $${paramIndex}::timestamptz`);
          params.push(options.beforeCreatedAt);
          paramIndex += 1;
        }

        params.push(boundedLimit);
        const limitParam = paramIndex;

        const { rows } = await client.query(
          `SELECT ${TEST_RUN_COLUMNS}
           FROM test_runs
           WHERE ${conditions.join(' AND ')}
           ORDER BY created_at DESC
           LIMIT $${limitParam}`,
          params,
        );
        return rows.map(mapTestRunRow);
      });
    },

    async getTestRun(ctx, id) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${TEST_RUN_COLUMNS}
           FROM test_runs
           WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        return mapTestRunRow(rows[0] ?? null);
      });
    },

    async createTestRun(ctx, record) {
      const tenantId = ctx.tenantId;
      const safetyConstraints = JSON.stringify(asObject(record.safety_constraints));
      const correlationJson = JSON.stringify(
        asObject(record.correlation ?? record.correlation_json),
      );
      const summaryJson = JSON.stringify(asObject(record.summary ?? record.summary_json));

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO test_runs (
             id, tenant_id, target_group_id, target_id, check_id, created_by, initiated_by,
             risk_class, safety_class, vector_family, status, probe_external_result,
             awaiting_external_probe, remediation_template, safety_constraints, correlation_json,
             collection_deadline_at, started_at, completed_at, summary_json, created_at
           )
           VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15::jsonb, $16::jsonb,
             $17::timestamptz, $18::timestamptz, $19::timestamptz, $20::jsonb, $21::timestamptz
           )
           RETURNING ${TEST_RUN_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.target_group_id,
            record.target_id ?? null,
            record.check_id,
            record.created_by ?? null,
            record.initiated_by ?? null,
            record.risk_class ?? null,
            record.safety_class ?? null,
            record.vector_family ?? null,
            record.status,
            record.probe_external_result ?? null,
            record.awaiting_external_probe ?? false,
            record.remediation_template ?? null,
            safetyConstraints,
            correlationJson,
            record.collection_deadline_at ?? null,
            record.started_at ?? null,
            record.completed_at ?? null,
            summaryJson,
            record.created_at,
          ],
        );
        return mapTestRunRow(rows[0]);
      });
    },

    async updateTestRun(ctx, id, patch) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const sets = [];
        const params = [];
        let paramIndex = 1;

        if (patch.status !== undefined) {
          sets.push(`status = $${paramIndex}`);
          params.push(patch.status);
          paramIndex += 1;
        }
        if (patch.probe_external_result !== undefined) {
          sets.push(`probe_external_result = $${paramIndex}`);
          params.push(patch.probe_external_result);
          paramIndex += 1;
        }
        if (patch.awaiting_external_probe !== undefined) {
          sets.push(`awaiting_external_probe = $${paramIndex}`);
          params.push(patch.awaiting_external_probe);
          paramIndex += 1;
        }
        if (patch.correlation !== undefined) {
          sets.push(`correlation_json = $${paramIndex}::jsonb`);
          params.push(JSON.stringify(asObject(patch.correlation)));
          paramIndex += 1;
        }
        if (patch.collection_deadline_at !== undefined) {
          sets.push(`collection_deadline_at = $${paramIndex}::timestamptz`);
          params.push(patch.collection_deadline_at);
          paramIndex += 1;
        }
        if (patch.completed_at !== undefined) {
          sets.push(`completed_at = $${paramIndex}::timestamptz`);
          params.push(patch.completed_at);
          paramIndex += 1;
        }
        if (patch.summary !== undefined) {
          sets.push(`summary_json = $${paramIndex}::jsonb`);
          params.push(JSON.stringify(asObject(patch.summary)));
          paramIndex += 1;
        }
        if (patch.safety_constraints !== undefined) {
          sets.push(`safety_constraints = $${paramIndex}::jsonb`);
          params.push(JSON.stringify(asObject(patch.safety_constraints)));
          paramIndex += 1;
        }

        if (sets.length === 0) {
          const { rows } = await client.query(
            `SELECT ${TEST_RUN_COLUMNS}
             FROM test_runs
             WHERE tenant_id = $1 AND id = $2`,
            [ctx.tenantId, id],
          );
          return mapTestRunRow(rows[0] ?? null);
        }

        params.push(ctx.tenantId, id);
        const tenantParam = paramIndex;
        const idParam = paramIndex + 1;

        const { rows } = await client.query(
          `UPDATE test_runs
           SET ${sets.join(', ')}
           WHERE tenant_id = $${tenantParam} AND id = $${idParam}
           RETURNING ${TEST_RUN_COLUMNS}`,
          params,
        );
        return mapTestRunRow(rows[0] ?? null);
      });
    },

    async appendEvent(ctx, record) {
      const tenantId = ctx.tenantId;
      const metadataJson = JSON.stringify(asObject(record.metadata ?? record.metadata_json));

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO events (
             id, tenant_id, event_id, test_run_id, target_id, check_id, agent_id, source,
             signal_type, nonce_hash, timestamp, metadata_json
           )
           VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::timestamptz, $12::jsonb
           )
           RETURNING ${EVENT_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.event_id ?? null,
            record.test_run_id ?? null,
            record.target_id ?? null,
            record.check_id ?? null,
            record.agent_id ?? null,
            record.source ?? null,
            record.signal_type ?? null,
            record.nonce_hash ?? null,
            record.timestamp,
            metadataJson,
          ],
        );
        return mapEventRow(rows[0]);
      });
    },

    async appendEventIdempotent(ctx, record) {
      if (record.event_id == null || record.event_id === '') {
        throw new Error(
          'appendEventIdempotent requires record.event_id; use appendEvent for non-idempotent local events',
        );
      }

      const tenantId = ctx.tenantId;
      const metadataJson = JSON.stringify(asObject(record.metadata ?? record.metadata_json));

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO events (
             id, tenant_id, event_id, test_run_id, target_id, check_id, agent_id, source,
             signal_type, nonce_hash, timestamp, metadata_json
           )
           VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::timestamptz, $12::jsonb
           )
           ON CONFLICT (tenant_id, event_id) WHERE event_id IS NOT NULL
           DO UPDATE SET
             test_run_id = EXCLUDED.test_run_id,
             target_id = EXCLUDED.target_id,
             check_id = EXCLUDED.check_id,
             agent_id = EXCLUDED.agent_id,
             source = EXCLUDED.source,
             signal_type = EXCLUDED.signal_type,
             nonce_hash = EXCLUDED.nonce_hash,
             timestamp = EXCLUDED.timestamp,
             metadata_json = EXCLUDED.metadata_json
           RETURNING ${EVENT_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.event_id,
            record.test_run_id ?? null,
            record.target_id ?? null,
            record.check_id ?? null,
            record.agent_id ?? null,
            record.source ?? null,
            record.signal_type ?? null,
            record.nonce_hash ?? null,
            record.timestamp,
            metadataJson,
          ],
        );
        return mapEventRow(rows[0]);
      });
    },

    async findEventByTenantEventId(ctx, eventId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${EVENT_COLUMNS}
           FROM events
           WHERE tenant_id = $1 AND event_id = $2`,
          [ctx.tenantId, eventId],
        );
        return mapEventRow(rows[0] ?? null);
      });
    },

    async listRunEvents(ctx, runId, options = {}) {
      const boundedLimit = normalizeRunEventsListLimit(options.limit);
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const params = [ctx.tenantId, runId];
        const conditions = ['tenant_id = $1', 'test_run_id = $2'];
        let paramIndex = 3;

        if (options.signalType != null && options.signalType !== '') {
          conditions.push(`signal_type = $${paramIndex}`);
          params.push(options.signalType);
          paramIndex += 1;
        }
        if (options.beforeTimestamp != null) {
          conditions.push(`timestamp < $${paramIndex}::timestamptz`);
          params.push(options.beforeTimestamp);
          paramIndex += 1;
        }

        params.push(boundedLimit);
        const limitParam = paramIndex;

        const { rows } = await client.query(
          `SELECT ${EVENT_COLUMNS}
           FROM events
           WHERE ${conditions.join(' AND ')}
           ORDER BY timestamp
           LIMIT $${limitParam}`,
          params,
        );
        return rows.map(mapEventRow);
      });
    },

    async appendProbeResultEventIdempotent(ctx, record) {
      if (record.test_run_id == null || record.test_run_id === '') {
        throw new Error('appendProbeResultEventIdempotent requires record.test_run_id');
      }
      if (record.nonce_hash == null || record.nonce_hash === '') {
        throw new Error('appendProbeResultEventIdempotent requires record.nonce_hash');
      }
      if (
        record.signal_type != null &&
        record.signal_type !== '' &&
        record.signal_type !== 'probe_result'
      ) {
        throw new Error(
          'appendProbeResultEventIdempotent only accepts signal_type probe_result',
        );
      }

      const tenantId = ctx.tenantId;
      const metadataJson = JSON.stringify(asObject(record.metadata ?? record.metadata_json));
      const signalType = 'probe_result';

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO events (
             id, tenant_id, event_id, test_run_id, target_id, check_id, agent_id, source,
             signal_type, nonce_hash, timestamp, metadata_json
           )
           VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::timestamptz, $12::jsonb
           )
           ON CONFLICT (tenant_id, test_run_id, signal_type, nonce_hash)
             WHERE signal_type = 'probe_result' AND nonce_hash IS NOT NULL
           DO UPDATE SET
             event_id = COALESCE(EXCLUDED.event_id, events.event_id),
             target_id = EXCLUDED.target_id,
             check_id = EXCLUDED.check_id,
             agent_id = EXCLUDED.agent_id,
             source = EXCLUDED.source,
             timestamp = EXCLUDED.timestamp,
             metadata_json = EXCLUDED.metadata_json
           RETURNING ${EVENT_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.event_id ?? null,
            record.test_run_id,
            record.target_id ?? null,
            record.check_id ?? null,
            record.agent_id ?? null,
            record.source ?? null,
            signalType,
            record.nonce_hash,
            record.timestamp,
            metadataJson,
          ],
        );
        return mapEventRow(rows[0]);
      });
    },

    async appendEvidence(ctx, record) {
      const tenantId = ctx.tenantId;
      const metadataJson = JSON.stringify(asObject(record.metadata ?? record.metadata_json));

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO evidence_vault (
             id, tenant_id, test_run_id, label, metadata_json, related_event_id, created_at
           )
           VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7::timestamptz)
           RETURNING ${EVIDENCE_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.test_run_id ?? null,
            record.label ?? null,
            metadataJson,
            record.related_event_id ?? null,
            record.created_at,
          ],
        );
        return mapEvidenceRow(rows[0]);
      });
    },

    async listEvidence(ctx, options = {}) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const rows = await queryEvidenceList(client, ctx.tenantId, options);
        return rows.map(mapEvidenceRow);
      });
    },

    async listEvidenceForRun(ctx, runId, options = {}) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const rows = await queryEvidenceList(client, ctx.tenantId, {
          ...options,
          testRunId: runId,
        });
        return rows.map(mapEvidenceRow);
      });
    },

    async getEvidence(ctx, id) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${EVIDENCE_COLUMNS}
           FROM evidence_vault
           WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        return mapEvidenceRow(rows[0] ?? null);
      });
    },

    async createVerdict(ctx, record) {
      const tenantId = ctx.tenantId;
      const evidenceIds = asStringArray(record.evidence_ids);
      const placementJson = placementConfidenceJson(record);

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO verdicts (
             id, tenant_id, test_run_id, target_id, check_id, verdict, confidence,
             explanation, evidence_ids, placement_confidence_json, created_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::timestamptz)
           RETURNING ${VERDICT_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.test_run_id,
            record.target_id ?? null,
            record.check_id ?? null,
            record.verdict,
            record.confidence ?? null,
            record.explanation ?? null,
            evidenceIds,
            placementJson,
            record.created_at,
          ],
        );
        return mapVerdictRow(rows[0]);
      });
    },

    async createVerdictIfAbsent(ctx, record) {
      const tenantId = ctx.tenantId;
      const evidenceIds = asStringArray(record.evidence_ids);
      const placementJson = placementConfidenceJson(record);

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO verdicts (
             id, tenant_id, test_run_id, target_id, check_id, verdict, confidence,
             explanation, evidence_ids, placement_confidence_json, created_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::timestamptz)
           ON CONFLICT (test_run_id)
           DO UPDATE SET
             target_id = EXCLUDED.target_id,
             check_id = EXCLUDED.check_id,
             verdict = EXCLUDED.verdict,
             confidence = EXCLUDED.confidence,
             explanation = EXCLUDED.explanation,
             evidence_ids = EXCLUDED.evidence_ids,
             placement_confidence_json = EXCLUDED.placement_confidence_json,
             created_at = EXCLUDED.created_at
           WHERE verdicts.tenant_id = EXCLUDED.tenant_id
           RETURNING ${VERDICT_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.test_run_id,
            record.target_id ?? null,
            record.check_id ?? null,
            record.verdict,
            record.confidence ?? null,
            record.explanation ?? null,
            evidenceIds,
            placementJson,
            record.created_at,
          ],
        );
        return mapVerdictRow(rows[0]);
      });
    },

    async getVerdictForRun(ctx, runId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${VERDICT_COLUMNS}
           FROM verdicts
           WHERE tenant_id = $1 AND test_run_id = $2`,
          [ctx.tenantId, runId],
        );
        return mapVerdictRow(rows[0] ?? null);
      });
    },

    async findOpenFinding(ctx, { target_group_id, target_id, check_id }) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${FINDING_COLUMNS}
           FROM findings
           WHERE tenant_id = $1
             AND target_group_id = $2
             AND target_id = $3
             AND check_id = $4
             AND status = 'open'`,
          [ctx.tenantId, target_group_id, target_id, check_id],
        );
        return mapFindingRow(rows[0] ?? null);
      });
    },

    async createFinding(ctx, record) {
      const tenantId = ctx.tenantId;
      const evidenceIds = asStringArray(record.evidence_ids);

      return withTenantContext(pool, tenantId, async (client) => {
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
            record.target_group_id ?? null,
            record.target_id ?? null,
            record.test_run_id ?? null,
            record.check_id ?? null,
            record.title,
            record.severity,
            record.status ?? 'open',
            evidenceIds,
            record.notes ?? null,
            record.remediation_template ?? null,
            record.verdict_id ?? null,
            record.last_verdict_id ?? null,
            record.assignee ?? null,
            record.created_at,
            record.updated_at ?? null,
          ],
        );
        return mapFindingRow(rows[0]);
      });
    },

    async upsertOpenFindingFromVerdict(ctx, record) {
      if (record.status !== undefined && record.status !== 'open') {
        throw new Error(
          `upsertOpenFindingFromVerdict only accepts open findings; got status ${JSON.stringify(record.status)}`,
        );
      }

      const tenantId = ctx.tenantId;
      const evidenceIds = asStringArray(record.evidence_ids);
      const status = 'open';
      const updatedAt = record.updated_at ?? new Date().toISOString();

      return withTenantContext(pool, tenantId, async (client) => {
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
           ON CONFLICT (tenant_id, target_group_id, target_id, check_id) WHERE status = 'open'
           DO UPDATE SET
             test_run_id = EXCLUDED.test_run_id,
             title = EXCLUDED.title,
             severity = EXCLUDED.severity,
             evidence_ids = EXCLUDED.evidence_ids,
             notes = EXCLUDED.notes,
             remediation_template = EXCLUDED.remediation_template,
             last_verdict_id = EXCLUDED.last_verdict_id,
             updated_at = EXCLUDED.updated_at
           RETURNING ${FINDING_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.target_group_id ?? null,
            record.target_id ?? null,
            record.test_run_id ?? null,
            record.check_id ?? null,
            record.title,
            record.severity,
            status,
            evidenceIds,
            record.notes ?? null,
            record.remediation_template ?? null,
            record.verdict_id ?? null,
            record.last_verdict_id ?? null,
            record.assignee ?? null,
            record.created_at,
            updatedAt,
          ],
        );
        return mapFindingRow(rows[0]);
      });
    },

    async patchFinding(ctx, id, patch) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const sets = [];
        const params = [];
        let paramIndex = 1;

        if (patch.status !== undefined) {
          sets.push(`status = $${paramIndex}`);
          params.push(patch.status);
          paramIndex += 1;
        }
        if (patch.assignee !== undefined) {
          sets.push(`assignee = $${paramIndex}`);
          params.push(patch.assignee);
          paramIndex += 1;
        }
        if (patch.notes !== undefined) {
          sets.push(`notes = $${paramIndex}`);
          params.push(patch.notes);
          paramIndex += 1;
        }
        if (patch.last_verdict_id !== undefined) {
          sets.push(`last_verdict_id = $${paramIndex}`);
          params.push(patch.last_verdict_id);
          paramIndex += 1;
        }
        if (patch.evidence_ids !== undefined) {
          sets.push(`evidence_ids = $${paramIndex}`);
          params.push(asStringArray(patch.evidence_ids));
          paramIndex += 1;
        }
        if (patch.updated_at !== undefined) {
          sets.push(`updated_at = $${paramIndex}::timestamptz`);
          params.push(patch.updated_at);
          paramIndex += 1;
        } else if (sets.length > 0) {
          sets.push(`updated_at = $${paramIndex}::timestamptz`);
          params.push(new Date().toISOString());
          paramIndex += 1;
        }

        if (sets.length === 0) {
          const { rows } = await client.query(
            `SELECT ${FINDING_COLUMNS}
             FROM findings
             WHERE tenant_id = $1 AND id = $2`,
            [ctx.tenantId, id],
          );
          return mapFindingRow(rows[0] ?? null);
        }

        params.push(ctx.tenantId, id);
        const tenantParam = paramIndex;
        const idParam = paramIndex + 1;

        const { rows } = await client.query(
          `UPDATE findings
           SET ${sets.join(', ')}
           WHERE tenant_id = $${tenantParam} AND id = $${idParam}
           RETURNING ${FINDING_COLUMNS}`,
          params,
        );
        return mapFindingRow(rows[0] ?? null);
      });
    },

    async listFindings(ctx) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${FINDING_COLUMNS}
           FROM findings
           WHERE tenant_id = $1
           ORDER BY created_at DESC`,
          [ctx.tenantId],
        );
        return rows.map(mapFindingRow);
      });
    },

    async getFinding(ctx, id) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${FINDING_COLUMNS}
           FROM findings
           WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        return mapFindingRow(rows[0] ?? null);
      });
    },
  };
}

export {
  mapTestRunRow,
  mapEventRow,
  mapEvidenceRow,
  mapVerdictRow,
  mapFindingRow,
};