export const PROMOTION_EVIDENCE_ENVIRONMENTS = Object.freeze(['staging', 'production']);

export function isDryRunEvidenceRecord(record = {}) {
  if (record.dry_run === true) return true;
  if (record.submittable === false) return true;
  if (record.collector_dry_run === true) return true;
  if (record.provenance?.dry_run === true) return true;
  if (record.provenance?.collector_dry_run === true) return true;
  if (record.evidence?.dry_run === true) return true;
  return false;
}

export function isNonSubmittableEvidenceRecord(record = {}) {
  if (isDryRunEvidenceRecord(record)) return true;
  const status = typeof record.status === 'string' ? record.status.trim().toLowerCase() : '';
  if (status === 'draft') return true;
  return false;
}

export function dryRunEvidenceRejection(body = {}) {
  if (body.dry_run === true) {
    return { error: 'dry_run_evidence_rejected', status: 400 };
  }
  if (body.submittable === false) {
    return { error: 'dry_run_evidence_rejected', status: 400 };
  }
  if (body.collector_dry_run === true) {
    return { error: 'dry_run_evidence_rejected', status: 400 };
  }
  if (isDryRunEvidenceRecord(body)) {
    return { error: 'dry_run_evidence_rejected', status: 400 };
  }
  return null;
}

export function assertSubmittableEvidenceRecord(record, contextLabel = 'record') {
  if (isNonSubmittableEvidenceRecord(record)) {
    const kind = record?.kind ?? 'unknown';
    throw new Error(`${contextLabel} (${kind}) is non-submittable dry-run or draft evidence`);
  }
}

export function assertSubmittableEvidencePayload(payload = {}, contextLabel = 'payload') {
  if (payload.dry_run === true || payload.submittable === false) {
    throw new Error(`${contextLabel} is marked dry-run or non-submittable`);
  }
  const records = Array.isArray(payload.records) ? payload.records : [];
  for (const record of records) {
    assertSubmittableEvidenceRecord(record, contextLabel);
  }
}

export function normalizeEvidenceReleaseId(releaseId) {
  if (releaseId === null || releaseId === undefined) return null;
  const normalized = String(releaseId).trim();
  return normalized || null;
}

export function recordReleaseId(record = {}) {
  return normalizeEvidenceReleaseId(record?.release_id);
}

export function recordBelongsToReleaseScope(record = {}, targetReleaseId = null) {
  const normalizedTarget = normalizeEvidenceReleaseId(targetReleaseId);
  const normalizedRecord = recordReleaseId(record);
  if (!normalizedTarget) return normalizedRecord === null;
  return normalizedRecord === normalizedTarget;
}

export function collectReleaseIds(records = []) {
  const ids = new Set();
  for (const record of records) {
    const normalized = recordReleaseId(record);
    if (normalized) ids.add(normalized);
  }
  return [...ids];
}

export function resolveAttestationReleaseScope(records = [], requestedReleaseId = null) {
  const normalizedRequest = normalizeEvidenceReleaseId(requestedReleaseId);
  const releaseIds = collectReleaseIds(records);

  if (normalizedRequest) {
    const scopedRecords = records.filter(
      (record) => recordReleaseId(record) === normalizedRequest,
    );
    return {
      releaseId: normalizedRequest,
      records: scopedRecords,
      mixedReleaseIds: false,
      releaseIds,
    };
  }

  if (releaseIds.length > 1) {
    return {
      releaseId: null,
      records: [],
      mixedReleaseIds: true,
      releaseIds,
    };
  }

  const inferredReleaseId = releaseIds[0] ?? null;
  if (inferredReleaseId) {
    const scopedRecords = records.filter(
      (record) => recordReleaseId(record) === inferredReleaseId,
    );
    return {
      releaseId: inferredReleaseId,
      records: scopedRecords,
      mixedReleaseIds: false,
      releaseIds,
    };
  }

  return {
    releaseId: null,
    records,
    mixedReleaseIds: false,
    releaseIds,
  };
}

export function promotionEnvironmentRejection(body = {}, options = {}) {
  const kind = body.kind;
  const evidence = body.evidence ?? {};
  const environment = evidence.environment;
  if (environment === null || environment === undefined || String(environment).trim() === '') {
    return null;
  }

  const normalized = String(environment).trim().toLowerCase();
  if (normalized === 'staging-sim') {
    return {
      error: 'simulated_environment_rejected',
      status: 400,
      environment: evidence.environment,
    };
  }

  const allowLocalStaging = options.allowLocalStaging === true;
  const allowed = allowLocalStaging
    ? [...PROMOTION_EVIDENCE_ENVIRONMENTS, 'local-staging']
    : [...PROMOTION_EVIDENCE_ENVIRONMENTS];

  if (!allowLocalStaging && normalized === 'local-staging') {
    return {
      error: 'local_staging_evidence_rejected',
      status: 400,
      environment: evidence.environment,
      allowed: [...PROMOTION_EVIDENCE_ENVIRONMENTS],
    };
  }

  if (!allowed.includes(normalized)) {
    return {
      error: 'invalid_promotion_environment',
      status: 400,
      environment: evidence.environment,
      allowed,
    };
  }

  if (kind && options.kindsWithEnvironmentField?.includes(kind) && !allowed.includes(normalized)) {
    return {
      error: 'invalid_promotion_environment',
      status: 400,
      environment: evidence.environment,
      allowed,
    };
  }

  return null;
}