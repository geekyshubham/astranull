import {
  aggregateStagingReadinessAttestation,
  isRehearsalOrSampleEvidenceInput,
  isSampleOrRehearsalReleaseId,
} from '../../../scripts/staging-readiness-attestation.mjs';
import { validateProductionReleaseEvidence } from '../../contracts/productionReleaseEvidence.mjs';
import { newId } from '../../lib/ids.mjs';
import { redactObject } from '../../lib/redact.mjs';

const ACCEPTED_EVIDENCE_STATUSES = new Set(['accepted', 'approved']);

export const PRODUCTION_RELEASE_EVIDENCE_REPOSITORY_METHODS = Object.freeze([
  'createProductionReleaseEvidence',
  'listProductionReleaseEvidence',
  'getProductionReleaseEvidence',
]);

export const POSTGRES_PRODUCTION_RELEASE_EVIDENCE_SERVICE_METHODS = Object.freeze([
  'recordProductionReleaseEvidence',
  'listProductionReleaseEvidence',
  'getProductionReleaseEvidence',
  'getProductionReleaseEvidenceAttestation',
]);

function assertProductionReleaseEvidenceRepositories(repositories) {
  const productionReleaseEvidence = repositories?.productionReleaseEvidence;
  if (!productionReleaseEvidence || typeof productionReleaseEvidence !== 'object') {
    throw new Error(
      'Postgres production release evidence service adapter requires repositories.productionReleaseEvidence.',
    );
  }
  for (const method of PRODUCTION_RELEASE_EVIDENCE_REPOSITORY_METHODS) {
    if (typeof productionReleaseEvidence[method] !== 'function') {
      throw new Error(
        `Postgres production release evidence service adapter requires productionReleaseEvidence.${method}().`,
      );
    }
  }

  const audit = repositories?.audit;
  if (!audit || typeof audit.appendAuditEvent !== 'function') {
    throw new Error(
      'Postgres production release evidence service adapter requires audit.appendAuditEvent().',
    );
  }
}

function validationError(validation) {
  if (validation.invalid_kind !== null) {
    return {
      error: 'invalid_evidence_kind',
      status: 400,
      invalid_kind: validation.invalid_kind,
    };
  }
  if (validation.missing_fields.length > 0) {
    return {
      error: 'missing_evidence_fields',
      status: 400,
      missing_fields: validation.missing_fields,
    };
  }
  if (validation.forbidden_fields.length > 0) {
    return {
      error: 'forbidden_evidence_fields',
      status: 400,
      forbidden_fields: validation.forbidden_fields,
    };
  }
  if (validation.invalid_fields.length > 0) {
    return {
      error: 'invalid_evidence_fields',
      status: 400,
      invalid_fields: validation.invalid_fields,
    };
  }
  return null;
}

function rehearsalEvidenceRejection(body = {}) {
  if (body.rehearsal_only === true) {
    return { error: 'rehearsal_evidence_rejected', status: 400 };
  }
  if (body.evidence?.rehearsal_only === true) {
    return { error: 'rehearsal_evidence_rejected', status: 400 };
  }
  const releaseId = body.release_id ?? null;
  if (isSampleOrRehearsalReleaseId(releaseId)) {
    return { error: 'rehearsal_evidence_rejected', status: 400 };
  }
  return null;
}

function isAcceptedEvidenceStatus(status) {
  const normalized = typeof status === 'string' ? status.trim().toLowerCase() : 'accepted';
  return ACCEPTED_EVIDENCE_STATUSES.has(normalized);
}

function attestationRecordSummary(record) {
  return {
    id: record.id,
    kind: record.kind,
    status: record.status,
    release_id: record.release_id ?? null,
    created_at: record.created_at,
    validation: record.validation ?? null,
  };
}

export function createPostgresProductionReleaseEvidenceServices(repositories, options = {}) {
  assertProductionReleaseEvidenceRepositories(repositories);
  const releaseEvidenceRepo = repositories.productionReleaseEvidence;
  const auditRepo = repositories.audit;
  const nowFn = options.now ?? (() => new Date());
  const newIdFn = options.newId ?? newId;

  return {
    async recordProductionReleaseEvidence(ctx, body = {}) {
      const rehearsalRejection = rehearsalEvidenceRejection(body);
      if (rehearsalRejection) return rehearsalRejection;

      const validation = validateProductionReleaseEvidence(body.kind, body.evidence);
      const error = validationError(validation);
      if (error) return error;

      const releaseId = body.release_id ?? null;
      const record = {
        id: newIdFn('evidence'),
        tenant_id: ctx.tenantId,
        kind: body.kind,
        release_id: releaseId,
        status: 'accepted',
        evidence: redactObject(body.evidence),
        notes: body.notes ? redactObject({ notes: body.notes }).notes : null,
        validation,
        created_at: nowFn().toISOString(),
        created_by: ctx.userId,
      };

      const persisted = await releaseEvidenceRepo.createProductionReleaseEvidence(ctx, record);
      await auditRepo.appendAuditEvent({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'production_release_evidence.recorded',
        resource_type: 'production_release_evidence',
        resource_id: persisted.id,
        metadata: {
          kind: persisted.kind,
          ...(releaseId ? { release_id: releaseId } : {}),
        },
      });
      return persisted;
    },

    async listProductionReleaseEvidence(ctx) {
      return releaseEvidenceRepo.listProductionReleaseEvidence(ctx);
    },

    async getProductionReleaseEvidence(ctx, id) {
      return releaseEvidenceRepo.getProductionReleaseEvidence(ctx, id);
    },

    async getProductionReleaseEvidenceAttestation(ctx) {
      const allRecords = await releaseEvidenceRepo.listProductionReleaseEvidence(ctx);
      const acceptedRecords = allRecords.filter((record) => isAcceptedEvidenceStatus(record.status));
      const releaseId = acceptedRecords.find((record) => record.release_id)?.release_id ?? null;

      const attestationInput = {
        releaseId,
        records: acceptedRecords.map((record) => ({
          kind: record.kind,
          evidence: record.evidence,
          status: record.status,
          release_id: record.release_id ?? null,
        })),
      };
      if (isRehearsalOrSampleEvidenceInput(attestationInput)) {
        attestationInput.rehearsal_only = true;
      }
      const attestation = aggregateStagingReadinessAttestation(attestationInput);

      return {
        attestation,
        records: acceptedRecords.map(attestationRecordSummary),
      };
    },
  };
}
