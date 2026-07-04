import {
  operatorAttestedEnvironmentRejection,
} from '../../scripts/submit-staging-evidence.mjs';
import {
  aggregateStagingReadinessAttestation,
  isRehearsalOrSampleEvidenceInput,
  isSampleOrRehearsalReleaseId,
} from '../../scripts/staging-readiness-attestation.mjs';
import {
  dryRunEvidenceRejection,
  resolveAttestationReleaseScope,
} from '../contracts/releaseEvidenceProvenance.mjs';
import { audit } from '../audit.mjs';
import { validateProductionReleaseEvidence } from '../contracts/productionReleaseEvidence.mjs';
import { newId } from '../lib/ids.mjs';
import { redactObject } from '../lib/redact.mjs';
import { getStore, persistStore } from '../store.mjs';

const ACCEPTED_EVIDENCE_STATUSES = new Set(['accepted', 'approved']);

function ensureLedger() {
  const store = getStore();
  if (!store.productionReleaseEvidence) store.productionReleaseEvidence = [];
  return store.productionReleaseEvidence;
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

export function recordProductionReleaseEvidence(ctx, body = {}) {
  const rehearsalRejection = rehearsalEvidenceRejection(body);
  if (rehearsalRejection) return rehearsalRejection;

  const dryRunRejection = dryRunEvidenceRejection(body);
  if (dryRunRejection) return dryRunRejection;

  const environmentRejection = operatorAttestedEnvironmentRejection(body);
  if (environmentRejection) return environmentRejection;

  const validation = validateProductionReleaseEvidence(body.kind, body.evidence);
  const error = validationError(validation);
  if (error) return error;

  const ledger = ensureLedger();
  const releaseId = body.release_id ?? null;
  const record = {
    id: newId('evidence'),
    tenant_id: ctx.tenantId,
    kind: body.kind,
    release_id: releaseId,
    status: 'accepted',
    evidence: redactObject(body.evidence),
    notes: body.notes ? redactObject({ notes: body.notes }).notes : null,
    validation,
    created_at: new Date().toISOString(),
    created_by: ctx.userId,
  };
  ledger.push(record);

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'production_release_evidence.recorded',
    resource_type: 'production_release_evidence',
    resource_id: record.id,
    metadata: {
      kind: record.kind,
      ...(releaseId ? { release_id: releaseId } : {}),
    },
  });
  persistStore();
  return record;
}

export function listProductionReleaseEvidence(ctx) {
  return ensureLedger().filter((record) => record.tenant_id === ctx.tenantId);
}

export function getProductionReleaseEvidence(ctx, id) {
  return ensureLedger().find((record) => record.id === id && record.tenant_id === ctx.tenantId) ?? null;
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

export function getProductionReleaseEvidenceAttestation(ctx, options = {}) {
  const requestedReleaseId = options.releaseId ?? options.release_id ?? null;
  const acceptedRecords = ensureLedger().filter(
    (record) => record.tenant_id === ctx.tenantId && isAcceptedEvidenceStatus(record.status),
  );
  const scope = resolveAttestationReleaseScope(acceptedRecords, requestedReleaseId);
  const scopedRecords = scope.records;

  const attestationInput = {
    releaseId: scope.releaseId,
    records: scopedRecords.map((record) => ({
      kind: record.kind,
      evidence: record.evidence,
      status: record.status,
      release_id: record.release_id ?? null,
      dry_run: record.dry_run,
      submittable: record.submittable,
      collector_dry_run: record.collector_dry_run,
    })),
    mixed_release_ids: scope.mixedReleaseIds,
    release_ids: scope.releaseIds,
  };
  if (isRehearsalOrSampleEvidenceInput(attestationInput)) {
    attestationInput.rehearsal_only = true;
  }
  const attestation = aggregateStagingReadinessAttestation(attestationInput);

  return {
    attestation,
    records: scopedRecords.map(attestationRecordSummary),
  };
}
