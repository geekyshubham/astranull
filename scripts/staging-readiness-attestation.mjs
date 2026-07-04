#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  PRODUCTION_RELEASE_EVIDENCE_KINDS,
  validateProductionReleaseEvidence,
} from '../src/contracts/productionReleaseEvidence.mjs';
import {
  isNonSubmittableEvidenceRecord,
  resolveAttestationReleaseScope,
} from '../src/contracts/releaseEvidenceProvenance.mjs';
import { redactObject } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/staging-readiness-attestation.json';

/** Default attestation profile: every production release evidence kind (conservative gate). */
export const DEFAULT_STAGING_READINESS_PROFILE = 'full';

/**
 * Kinds required by release profiles before/without a matching production contract entry.
 * Once a kind appears in PRODUCTION_RELEASE_EVIDENCE_KINDS, contract validation takes precedence.
 */
export const STAGING_READINESS_PENDING_CONTRACT_REQUIREMENTS = Object.freeze({
  staging_e2e_matrix: Object.freeze([
    'schema_version',
    'artifact_type',
    'created_at',
    'release_id',
    'environment',
    'scenarios',
    'overall_status',
    'signoff',
    'evidence_uri',
  ]),
  control_plane_container_release: Object.freeze([
    'schema_version',
    'artifact_type',
    'created_at',
    'release_id',
    'image',
    'scan_summary',
    'signing_summary',
    'promotion_summary',
    'rollback_reference',
    'evidence_uri',
  ]),
  kms_vault_posture: Object.freeze([
    'schema_version',
    'artifact_type',
    'created_at',
    'validation',
    'environment',
    'vault_summary',
    'key_rotation_policy',
    'access_control_summary',
    'drill_reference',
    'security_signoff',
    'evidence_uri',
  ]),
  authorization_custody: Object.freeze([
    'schema_version',
    'artifact_type',
    'created_at',
    'release_id',
    'custody_summary',
    'required_artifacts',
    'retention_policy',
    'legal_signoff',
    'evidence_uri',
  ]),
  placement_confidence_staging: Object.freeze([
    'schema_version',
    'artifact_type',
    'created_at',
    'release_id',
    'environment',
    'scenarios',
    'evidence_correlation_summary',
    'signoff',
    'evidence_uri',
  ]),
  gateway_load_abuse: Object.freeze([
    'schema_version',
    'artifact_type',
    'created_at',
    'release_id',
    'environment',
    'rate_limit_results',
    'abuse_detection_results',
    'edge_alerting_summary',
    'signoff',
    'evidence_uri',
  ]),
});

const PENDING_CONTRACT_KIND_SET = new Set(Object.keys(STAGING_READINESS_PENDING_CONTRACT_REQUIREMENTS));

const HIGH_SCALE_GA_EXTRA_KINDS = Object.freeze([
  'governed_adapter',
  'provider_approval',
  'kill_switch_drill',
  'authorization_custody',
  'placement_confidence_staging',
  'gateway_load_abuse',
]);

const SAFE_VALIDATION_GA_EXTRA_KINDS = Object.freeze([
  'staging_e2e_matrix',
  'control_plane_container_release',
  'kms_vault_posture',
]);

const HIGH_SCALE_ONLY_KIND_SET = new Set(HIGH_SCALE_GA_EXTRA_KINDS);

function buildSafeValidationGaKinds() {
  const base = PRODUCTION_RELEASE_EVIDENCE_KINDS.filter((kind) => !HIGH_SCALE_ONLY_KIND_SET.has(kind));
  return Object.freeze([...new Set([...base, ...SAFE_VALIDATION_GA_EXTRA_KINDS])]);
}

const SAFE_VALIDATION_GA_KINDS = buildSafeValidationGaKinds();

function buildHighScaleGaKinds() {
  return Object.freeze([...new Set([...SAFE_VALIDATION_GA_KINDS, ...HIGH_SCALE_GA_EXTRA_KINDS])]);
}

const HIGH_SCALE_GA_KINDS = buildHighScaleGaKinds();

export const STAGING_READINESS_RELEASE_PROFILES = Object.freeze({
  'safe-validation-ga': SAFE_VALIDATION_GA_KINDS,
  'high-scale-ga': HIGH_SCALE_GA_KINDS,
  full: Object.freeze([...PRODUCTION_RELEASE_EVIDENCE_KINDS]),
});

/** Documented optional / future evidence kinds (not required for production_ready). */
export const STAGING_READINESS_OPTIONAL_EVIDENCE_KINDS = Object.freeze([]);

const OPTIONAL_KIND_SET = new Set(STAGING_READINESS_OPTIONAL_EVIDENCE_KINDS.map((entry) => entry.kind));
const ACCEPTED_STATUSES = new Set(['accepted', 'approved']);

export function resolveReleaseProfileKinds(profile = DEFAULT_STAGING_READINESS_PROFILE) {
  const normalized = typeof profile === 'string' ? profile.trim().toLowerCase() : '';
  const kinds = STAGING_READINESS_RELEASE_PROFILES[normalized];
  if (!kinds) {
    const allowed = Object.keys(STAGING_READINESS_RELEASE_PROFILES).join(', ');
    throw new Error(`Unknown release profile "${profile}". Allowed profiles: ${allowed}`);
  }
  return kinds;
}

function hasValue(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string' && value.trim() === '') return false;
  return true;
}

function validatePendingContractEvidence(kind, evidence) {
  const required = STAGING_READINESS_PENDING_CONTRACT_REQUIREMENTS[kind];
  if (!required) {
    return {
      ok: false,
      invalid_kind: kind,
      missing_fields: [],
      forbidden_fields: scanForbiddenMetadata(evidence),
      invalid_fields: [],
    };
  }
  const missing_fields = required.filter((field) => !hasValue(evidence?.[field]));
  const forbidden_fields = scanForbiddenMetadata(evidence);
  return {
    ok: missing_fields.length === 0 && forbidden_fields.length === 0,
    invalid_kind: null,
    missing_fields,
    forbidden_fields,
    invalid_fields: [],
  };
}

function validateEvidenceForKind(kind, evidence) {
  if (PRODUCTION_RELEASE_EVIDENCE_KINDS.includes(kind)) {
    return validateProductionReleaseEvidence(kind, evidence);
  }
  if (PENDING_CONTRACT_KIND_SET.has(kind)) {
    return validatePendingContractEvidence(kind, evidence);
  }
  return {
    ok: false,
    invalid_kind: kind,
    missing_fields: [],
    forbidden_fields: scanForbiddenMetadata(evidence),
    invalid_fields: [],
  };
}

function isDocumentedEvidenceKind(kind) {
  return PRODUCTION_RELEASE_EVIDENCE_KINDS.includes(kind)
    || PENDING_CONTRACT_KIND_SET.has(kind)
    || OPTIONAL_KIND_SET.has(kind);
}

export function parseArgs(argv = []) {
  const opts = {
    input: null,
    out: DEFAULT_OUT,
    releaseId: null,
    profile: DEFAULT_STAGING_READINESS_PROFILE,
    validateOnly: false,
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`Missing value for ${arg}`);
      return argv[i];
    };
    if (arg === '--input') opts.input = next();
    else if (arg === '--out') opts.out = next();
    else if (arg === '--release-id') opts.releaseId = next();
    else if (arg === '--profile') opts.profile = next();
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!opts.help && !opts.input) throw new Error('--input is required');
  if (!opts.help) resolveReleaseProfileKinds(opts.profile);
  return opts;
}

function scanForbiddenMetadata(value) {
  return validateProductionReleaseEvidence('__metadata_scan__', value).forbidden_fields;
}

export function normalizeEvidenceRecords(parsed) {
  if (Array.isArray(parsed)) return parsed;
  if (Array.isArray(parsed?.records)) return parsed.records;
  throw new Error('Input must be an array or an object with records[].');
}

function optionalKindMeta(kind) {
  return STAGING_READINESS_OPTIONAL_EVIDENCE_KINDS.find((entry) => entry.kind === kind) ?? null;
}

function normalizeStatus(record) {
  const raw = record?.status ?? 'accepted';
  return typeof raw === 'string' ? raw.trim().toLowerCase() : 'accepted';
}

function isAcceptedStatus(status) {
  return ACCEPTED_STATUSES.has(status);
}

/** True when a release id denotes generated sample or rehearsal inventory (not production signoff). */
export function isSampleOrRehearsalReleaseId(releaseId) {
  if (releaseId === null || releaseId === undefined) return false;
  const normalized = String(releaseId).trim().toLowerCase();
  if (!normalized) return false;
  if (normalized === 'rel-sample-rehearsal') return true;
  if (normalized.startsWith('rel_sample')) return true;
  if (normalized.startsWith('rel-sample')) return true;
  if (normalized.includes('rehearsal')) return true;
  return false;
}

/** Detect rehearsal/sample evidence inputs before aggregating production readiness. */
export function isRehearsalOrSampleEvidenceInput(input = {}) {
  if (input.rehearsal_only === true) return true;
  const topReleaseId = input.releaseId ?? input.release_id ?? null;
  if (isSampleOrRehearsalReleaseId(topReleaseId)) return true;
  const records = Array.isArray(input.records) ? input.records : [];
  for (const record of records) {
    if (record?.rehearsal_only === true) return true;
    if (isSampleOrRehearsalReleaseId(record?.release_id)) return true;
    if (record?.evidence?.rehearsal_only === true) return true;
  }
  return false;
}

function buildAttestationCaveats({ profile, productionReady, rehearsalOnly }) {
  const base = [
    'Metadata-only attestation gate; does not simulate staging workloads or execute probes.',
    'Operator, security, and legal signoff in staging still required beyond this evidence inventory.',
  ];
  if (rehearsalOnly) {
    return [
      ...base,
      'Sample/rehearsal evidence is for local walkthrough only; it cannot satisfy production readiness.',
    ];
  }
  if (productionReady) {
    return [
      ...base,
      'production_ready=true means profile inventory complete; it is not promotion approval.',
    ];
  }
  return [
    ...base,
    'production_ready=false means required profile inventory is missing, invalid, rejected, unknown, or rehearsal-only.',
  ];
}

export function assessEvidenceRecord(record) {
  const kind = record?.kind;
  const evidence = record?.evidence ?? {};
  const status = normalizeStatus(record);
  if (isNonSubmittableEvidenceRecord(record)) {
    return {
      kind,
      required: PRODUCTION_RELEASE_EVIDENCE_KINDS.includes(kind),
      optional: false,
      future: false,
      status,
      accepted: false,
      validation: {
        ok: false,
        invalid_kind: null,
        missing_fields: [],
        forbidden_fields: [],
        invalid_fields: [{ field: 'provenance', reason: 'non_submittable_evidence' }],
      },
      unknown_kind: false,
      non_submittable: true,
    };
  }
  const optionalMeta = optionalKindMeta(kind);
  const contractKind = PRODUCTION_RELEASE_EVIDENCE_KINDS.includes(kind);
  const pendingKind = PENDING_CONTRACT_KIND_SET.has(kind);

  if (!isDocumentedEvidenceKind(kind)) {
    return {
      kind,
      required: false,
      optional: false,
      future: false,
      status,
      accepted: false,
      validation: {
        ok: false,
        invalid_kind: kind,
        missing_fields: [],
        forbidden_fields: [],
        invalid_fields: [],
      },
      unknown_kind: true,
    };
  }

  const validation = contractKind || pendingKind || optionalMeta
    ? validateEvidenceForKind(kind, evidence)
    : {
      ok: false,
      invalid_kind: kind,
      missing_fields: [],
      forbidden_fields: scanForbiddenMetadata(evidence),
      invalid_fields: [],
    };

  if (optionalMeta && validation.invalid_kind) {
    const forbiddenOnly = scanForbiddenMetadata(evidence);
    const optionalOk = forbiddenOnly.length === 0 && isAcceptedStatus(status);
    return {
      kind,
      required: false,
      optional: optionalMeta.optional,
      future: optionalMeta.future,
      status,
      accepted: optionalOk,
      validation: {
        ok: optionalOk,
        invalid_kind: null,
        missing_fields: [],
        forbidden_fields: forbiddenOnly,
        invalid_fields: [],
      },
      unknown_kind: false,
    };
  }

  const contractOk = validation.ok;
  const accepted = contractOk && isAcceptedStatus(status);

  return {
    kind,
    required: contractKind || pendingKind,
    optional: Boolean(optionalMeta),
    future: optionalMeta?.future ?? false,
    status,
    accepted,
    validation,
    unknown_kind: false,
  };
}

function pickBestAssessment(assessments) {
  const accepted = assessments.filter((entry) => entry.accepted);
  if (accepted.length > 0) return accepted[0];
  const validShape = assessments.filter((entry) => entry.validation.ok);
  if (validShape.length > 0) return validShape[0];
  return assessments[0];
}

export function aggregateStagingReadinessAttestation(input = {}, options = {}) {
  const profile = options.profile ?? DEFAULT_STAGING_READINESS_PROFILE;
  const requiredKinds = options.requiredKinds ?? resolveReleaseProfileKinds(profile);
  const inputForbidden = scanForbiddenMetadata(input);
  if (inputForbidden.length > 0) {
    throw new Error(`Input contains forbidden metadata field(s): ${inputForbidden.join(', ')}`);
  }

  const requestedReleaseId = input.releaseId ?? input.release_id ?? null;
  const scope = input.mixed_release_ids === true
    ? {
      releaseId: null,
      records: [],
      mixedReleaseIds: true,
      releaseIds: input.release_ids ?? [],
    }
    : resolveAttestationReleaseScope(
      Array.isArray(input.records) ? input.records : [],
      requestedReleaseId,
    );
  const records = scope.records;
  const releaseId = scope.releaseId;
  const mixedReleaseIds = scope.mixedReleaseIds;

  const assessmentsByKind = new Map();
  const unknownKinds = [];

  for (const record of records) {
    const assessment = assessEvidenceRecord(record);
    if (assessment.unknown_kind) {
      unknownKinds.push(assessment.kind);
      continue;
    }
    const list = assessmentsByKind.get(assessment.kind) ?? [];
    list.push(assessment);
    assessmentsByKind.set(assessment.kind, list);
  }

  const presentRequired = [];
  const missingRequired = [];
  const invalidRequired = [];
  const rejectedRequired = [];

  for (const kind of requiredKinds) {
    const assessments = assessmentsByKind.get(kind) ?? [];
    if (assessments.length === 0) {
      missingRequired.push(kind);
      continue;
    }
    const best = pickBestAssessment(assessments);
    if (best.accepted) {
      presentRequired.push(kind);
      continue;
    }
    if (!isAcceptedStatus(best.status)) {
      rejectedRequired.push({ kind, status: best.status });
    } else if (!best.validation.ok) {
      invalidRequired.push({
        kind,
        missing_fields: best.validation.missing_fields,
        forbidden_fields: best.validation.forbidden_fields,
        invalid_fields: best.validation.invalid_fields ?? [],
      });
    } else {
      invalidRequired.push({
        kind,
        missing_fields: [],
        forbidden_fields: [],
        invalid_fields: [],
      });
    }
  }

  const optionalPresent = [];
  for (const entry of STAGING_READINESS_OPTIONAL_EVIDENCE_KINDS) {
    const assessments = assessmentsByKind.get(entry.kind) ?? [];
    if (assessments.length === 0) continue;
    const best = pickBestAssessment(assessments);
    optionalPresent.push({
      kind: entry.kind,
      optional: entry.optional,
      future: entry.future,
      accepted: best.accepted,
      status: best.status,
    });
  }

  const blockers = [];
  if (mixedReleaseIds) {
    const ids = scope.releaseIds?.length ? scope.releaseIds.join(', ') : 'multiple';
    blockers.push(`Mixed release_id values in attestation scope (${ids}); provide a single release_id filter.`);
  }
  if (missingRequired.length > 0) {
    blockers.push(`Missing required evidence kind(s): ${missingRequired.join(', ')}`);
  }
  for (const entry of invalidRequired) {
    const parts = [];
    if (entry.missing_fields?.length) parts.push(`missing ${entry.missing_fields.join(', ')}`);
    if (entry.forbidden_fields?.length) parts.push(`forbidden ${entry.forbidden_fields.join(', ')}`);
    if (entry.invalid_fields?.length) {
      const invalidSummary = entry.invalid_fields
        .map((item) => (typeof item === 'object' && item?.field ? item.field : String(item)))
        .join(', ');
      parts.push(`invalid ${invalidSummary}`);
    }
    blockers.push(`Invalid ${entry.kind} evidence (${parts.join('; ') || 'validation failed'})`);
  }
  for (const entry of rejectedRequired) {
    blockers.push(`Rejected evidence for ${entry.kind} (status=${entry.status})`);
  }
  if (unknownKinds.length > 0) {
    blockers.push(`Unknown evidence kind(s): ${[...new Set(unknownKinds)].join(', ')}`);
  }

  const evidenceComplete = !mixedReleaseIds
    && missingRequired.length === 0
    && invalidRequired.length === 0
    && rejectedRequired.length === 0
    && unknownKinds.length === 0;

  const rehearsalOnly = isRehearsalOrSampleEvidenceInput(input);
  const inventoryProductionReady = evidenceComplete;
  const productionReady = inventoryProductionReady && !rehearsalOnly;

  if (rehearsalOnly) {
    blockers.push('Rehearsal/sample evidence cannot satisfy production readiness.');
  }

  let signoffStatus = 'blocked';
  if (rehearsalOnly) signoffStatus = 'rehearsal_only';
  else if (productionReady) signoffStatus = 'evidence_complete';
  else if (missingRequired.length > 0 && invalidRequired.length === 0 && rejectedRequired.length === 0) {
    signoffStatus = 'missing_evidence';
  } else if (invalidRequired.length > 0 || rejectedRequired.length > 0 || unknownKinds.length > 0) {
    signoffStatus = 'invalid_evidence';
  }

  const caveats = buildAttestationCaveats({ profile, productionReady, rehearsalOnly });

  return {
    schema_version: 1,
    artifact_type: 'staging_readiness_attestation',
    created_at: input.createdAt ?? new Date().toISOString(),
    release_id: releaseId,
    profile,
    production_ready: productionReady,
    signoff_status: signoffStatus,
    required_evidence_kinds: {
      profile,
      required: [...requiredKinds],
      present: presentRequired,
      missing: missingRequired,
      invalid: invalidRequired,
      rejected: rejectedRequired,
    },
    optional_evidence_kinds: {
      documented: STAGING_READINESS_OPTIONAL_EVIDENCE_KINDS.map((entry) => ({
        kind: entry.kind,
        optional: entry.optional,
        future: entry.future,
      })),
      present: optionalPresent,
    },
    blocker_summary: blockers,
    record_counts: {
      total: records.length,
      required_kinds_with_records: [...assessmentsByKind.keys()].filter((kind) => requiredKinds.includes(kind)).length,
    },
    caveats,
    ...(rehearsalOnly ? { rehearsal_only: true } : {}),
    ...(input.notes ? { notes: redactObject({ notes: input.notes }).notes } : {}),
  };
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/staging-readiness-attestation.mjs --input evidence.json '
      + `[--profile ${DEFAULT_STAGING_READINESS_PROFILE}|safe-validation-ga|high-scale-ga] `
      + '[--release-id rel] [--out file] [--validate-only]',
    );
    return 0;
  }

  const parsed = JSON.parse(readFileSync(opts.input, 'utf8'));
  const forbiddenInFile = scanForbiddenMetadata(parsed);
  if (forbiddenInFile.length > 0) {
    throw new Error(`Input file contains forbidden metadata field(s): ${forbiddenInFile.join(', ')}`);
  }

  const attestation = aggregateStagingReadinessAttestation({
    releaseId: opts.releaseId ?? parsed.release_id ?? null,
    records: normalizeEvidenceRecords(parsed),
    createdAt: parsed.created_at ?? null,
    notes: parsed.notes ?? null,
    rehearsalOnly: parsed.rehearsal_only === true,
  }, { profile: opts.profile });

  if (opts.validateOnly) {
    if (!attestation.production_ready) {
      console.error(
        `staging-readiness-attestation: evidence inventory incomplete `
        + `(${attestation.blocker_summary.length} blocker(s)); production promotion gates remain external`,
      );
      for (const blocker of attestation.blocker_summary) {
        console.error(`  - ${blocker}`);
      }
      return 1;
    }
    console.log(
      `staging-readiness-attestation: ok (inventory_complete=true, production_ready=true, `
      + `profile=${attestation.profile}, ${attestation.required_evidence_kinds.present.length} `
      + `required kind(s); not promotion approval)`,
    );
    return 0;
  }

  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(attestation, null, 2)}\n`);
  console.log(
    `staging-readiness-attestation: wrote ${opts.out} `
    + `(inventory_complete=${attestation.production_ready}, production_ready=${attestation.production_ready}, `
    + `profile=${attestation.profile}; not promotion approval)`,
  );
  return attestation.production_ready ? 0 : 1;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`staging-readiness-attestation: ${err.message}`);
      process.exit(1);
    },
  );
}