#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  PRODUCTION_RELEASE_EVIDENCE_KINDS,
  PRODUCTION_RELEASE_EVIDENCE_REQUIREMENTS,
} from '../src/contracts/productionReleaseEvidence.mjs';
import {
  assertSubmittableEvidencePayload,
  assertSubmittableEvidenceRecord,
} from '../src/contracts/releaseEvidenceProvenance.mjs';
import {
  createReleaseEvidenceBundle,
  parseInputJson,
  validateEvidenceRecord,
} from './release-evidence-bundle.mjs';
import {
  DEFAULT_STAGING_READINESS_PROFILE,
  isRehearsalOrSampleEvidenceInput,
  normalizeEvidenceRecords,
  resolveReleaseProfileKinds,
} from './staging-readiness-attestation.mjs';

const DEFAULT_OUT = 'output/staging-evidence-submission-summary.json';

export const PRODUCTION_PROMOTION_PROFILE = DEFAULT_STAGING_READINESS_PROFILE;

export const OPERATOR_ATTESTED_ENVIRONMENTS = Object.freeze(['staging', 'production']);
export const LOCAL_STAGING_SIMULATOR_ENVIRONMENTS = Object.freeze(['local-staging']);

export const EVIDENCE_KINDS_WITH_ENVIRONMENT_FIELD = Object.freeze(
  PRODUCTION_RELEASE_EVIDENCE_KINDS.filter((kind) =>
    PRODUCTION_RELEASE_EVIDENCE_REQUIREMENTS[kind].includes('environment')),
);

function hasValue(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string' && value.trim() === '') return false;
  return true;
}

export function normalizeEnvironmentLabel(value) {
  if (!hasValue(value)) return null;
  return String(value).trim().toLowerCase();
}

export function isSimulatedEnvironment(value) {
  return normalizeEnvironmentLabel(value) === 'staging-sim';
}

export function isOperatorAttestedEnvironment(value) {
  const normalized = normalizeEnvironmentLabel(value);
  return OPERATOR_ATTESTED_ENVIRONMENTS.includes(normalized);
}

export function isLocalStagingSimulatorEnvironment(value) {
  const normalized = normalizeEnvironmentLabel(value);
  return LOCAL_STAGING_SIMULATOR_ENVIRONMENTS.includes(normalized);
}

export function isPromotionEligibleEnvironment(value, options = {}) {
  if (isOperatorAttestedEnvironment(value)) return true;
  if (options.allowLocalStaging === true && isLocalStagingSimulatorEnvironment(value)) return true;
  return false;
}

export function parseArgs(argv = []) {
  const opts = {
    input: null,
    out: DEFAULT_OUT,
    baseUrl: null,
    releaseId: null,
    profile: PRODUCTION_PROMOTION_PROFILE,
    tenantId: 'ten_demo',
    userId: 'usr_release_operator',
    role: 'admin',
    authToken: null,
    validateOnly: false,
    dryRun: false,
    allowRehearsal: false,
    allowLocalStaging: false,
    continueOnError: false,
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
    else if (arg === '--base-url') opts.baseUrl = next();
    else if (arg === '--release-id') opts.releaseId = next();
    else if (arg === '--profile') opts.profile = next();
    else if (arg === '--tenant-id') opts.tenantId = next();
    else if (arg === '--user-id') opts.userId = next();
    else if (arg === '--role') opts.role = next();
    else if (arg === '--auth-token') opts.authToken = next();
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--dry-run') opts.dryRun = true;
    else if (arg === '--allow-rehearsal') opts.allowRehearsal = true;
    else if (arg === '--allow-local-staging') opts.allowLocalStaging = true;
    else if (arg === '--continue-on-error') opts.continueOnError = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!opts.help && !opts.input) throw new Error('--input is required');
  if (!opts.help) resolveReleaseProfileKinds(opts.profile);
  if (!opts.help && !opts.validateOnly && !opts.dryRun && !opts.baseUrl) {
    throw new Error('--base-url is required unless --validate-only or --dry-run is set');
  }
  return opts;
}

export function parseSubmissionInput(inputPath) {
  const raw = JSON.parse(readFileSync(inputPath, 'utf8'));
  const parsed = parseInputJson(inputPath);
  const records = normalizeEvidenceRecords(parsed);
  return {
    records,
    release_id: parsed.release_id ?? raw.release_id ?? null,
    environment: raw.environment ?? null,
    rehearsal_only: parsed.rehearsal_only,
    artifact_type: parsed.artifact_type ?? null,
    schema_version: parsed.schema_version ?? null,
    created_at: parsed.createdAt ?? parsed.created_at ?? null,
    notes: parsed.notes ?? null,
  };
}

function assertAcceptedRecordStatus(record) {
  const status = typeof record?.status === 'string' ? record.status.trim().toLowerCase() : 'accepted';
  if (status !== 'accepted' && status !== 'approved') {
    throw new Error(`${record?.kind ?? 'unknown'} record must have status accepted or approved (got ${status})`);
  }
}

function validatePromotionEnvironmentValue(value, contextLabel, options = {}) {
  if (isSimulatedEnvironment(value)) {
    throw new Error(
      `${contextLabel} uses simulated environment "staging-sim"; operator-attested staging or production evidence is required`,
    );
  }
  if (!isPromotionEligibleEnvironment(value, options)) {
    const allowed = options.allowLocalStaging
      ? [...OPERATOR_ATTESTED_ENVIRONMENTS, ...LOCAL_STAGING_SIMULATOR_ENVIRONMENTS]
      : [...OPERATOR_ATTESTED_ENVIRONMENTS];
    throw new Error(
      `${contextLabel} environment must be one of ${allowed.join(', ')} for production promotion profile (got ${value ?? 'missing'})`,
    );
  }
}

export function validateRecordPromotionEnvironment(record, options = {}) {
  const kind = record?.kind;
  const evidence = record?.evidence ?? {};
  const requiresEnvironment = EVIDENCE_KINDS_WITH_ENVIRONMENT_FIELD.includes(kind);

  if (hasValue(evidence.environment)) {
    validatePromotionEnvironmentValue(evidence.environment, `${kind} evidence`, options);
  } else if (requiresEnvironment) {
    const allowed = options.allowLocalStaging
      ? [...OPERATOR_ATTESTED_ENVIRONMENTS, ...LOCAL_STAGING_SIMULATOR_ENVIRONMENTS]
      : [...OPERATOR_ATTESTED_ENVIRONMENTS];
    throw new Error(
      `${kind} evidence.environment must be one of ${allowed.join(', ')} for production promotion profile`,
    );
  }
}

export function operatorAttestedEnvironmentRejection(body = {}, options = {}) {
  const kind = body.kind;
  const evidence = body.evidence ?? {};
  if (isSimulatedEnvironment(evidence.environment)) {
    return {
      error: 'simulated_environment_rejected',
      status: 400,
      environment: evidence.environment,
    };
  }
  if (!EVIDENCE_KINDS_WITH_ENVIRONMENT_FIELD.includes(kind)) {
    return null;
  }
  const allowLocalStaging = options.allowLocalStaging === true;
  if (
    !isOperatorAttestedEnvironment(evidence.environment)
    && !(allowLocalStaging && isLocalStagingSimulatorEnvironment(evidence.environment))
  ) {
    const allowed = allowLocalStaging
      ? [...OPERATOR_ATTESTED_ENVIRONMENTS, ...LOCAL_STAGING_SIMULATOR_ENVIRONMENTS]
      : [...OPERATOR_ATTESTED_ENVIRONMENTS];
    const error = isLocalStagingSimulatorEnvironment(evidence.environment)
      ? 'local_staging_evidence_rejected'
      : 'invalid_promotion_environment';
    return {
      error,
      status: 400,
      environment: evidence.environment ?? null,
      allowed,
    };
  }
  return null;
}

export function validateOperatorAttestedRecords(input = {}, options = {}) {
  const records = Array.isArray(input.records) ? input.records : [];
  if (records.length === 0) throw new Error('At least one evidence record is required.');

  if (input.dry_run === true || input.submittable === false) {
    throw new Error('Dry-run or non-submittable evidence cannot be submitted.');
  }
  assertSubmittableEvidencePayload(input, 'Submission payload');

  const allowRehearsal = options.allowRehearsal === true;
  const profile = options.profile ?? PRODUCTION_PROMOTION_PROFILE;
  resolveReleaseProfileKinds(profile);

  if (!allowRehearsal && isRehearsalOrSampleEvidenceInput({
    rehearsal_only: input.rehearsal_only,
    releaseId: input.releaseId ?? input.release_id ?? null,
    records,
  })) {
    throw new Error('Rehearsal/sample evidence cannot be submitted; replace with operator-attested staging records.');
  }

  const promotionOptions = { allowLocalStaging: options.allowLocalStaging === true };

  if (hasValue(input.environment)) {
    validatePromotionEnvironmentValue(input.environment, 'Submission payload', promotionOptions);
  }

  const bundle = createReleaseEvidenceBundle({
    releaseId: input.releaseId ?? input.release_id ?? null,
    records,
    createdAt: input.createdAt ?? input.created_at ?? undefined,
    rehearsal_only: allowRehearsal ? input.rehearsal_only : undefined,
  }, { allowRehearsalSampleBundle: allowRehearsal });

  const validatedRecords = [];
  for (const record of records) {
    assertSubmittableEvidenceRecord(record, 'Submission record');
    assertAcceptedRecordStatus(record);
    validateRecordPromotionEnvironment(record, promotionOptions);
    const validated = validateEvidenceRecord(record);
    validatedRecords.push({
      kind: validated.kind,
      evidence: validated.evidence,
      validation: validated.validation,
      release_id: record.release_id ?? bundle.release_id ?? null,
      ...(record.notes ? { notes: validated.notes ?? record.notes } : {}),
      status: typeof record.status === 'string' ? record.status.trim().toLowerCase() : 'accepted',
    });
  }

  return {
    profile,
    release_id: input.releaseId ?? input.release_id ?? bundle.release_id ?? null,
    environment: input.environment ?? null,
    records: validatedRecords,
    bundle,
    required_kinds: resolveReleaseProfileKinds(profile),
  };
}

export function buildSubmissionBodies(input = {}, options = {}) {
  const validated = validateOperatorAttestedRecords(input, options);
  return validated.records.map((record) => ({
    kind: record.kind,
    evidence: record.evidence,
    release_id: record.release_id ?? validated.release_id ?? null,
    ...(record.notes ? { notes: record.notes } : {}),
  }));
}

function submissionHeaders(options = {}) {
  if (options.authToken) {
    return {
      Authorization: `Bearer ${options.authToken}`,
      'Content-Type': 'application/json',
    };
  }
  return {
    'x-tenant-id': options.tenantId,
    'x-user-id': options.userId,
    'x-role': options.role,
    'Content-Type': 'application/json',
  };
}

async function postEvidenceRecord(baseUrl, body, options = {}) {
  const fetchFn = options.fetchFn ?? fetch;
  const response = await fetchFn(`${baseUrl.replace(/\/$/, '')}/v1/production-release-evidence`, {
    method: 'POST',
    headers: submissionHeaders(options),
    body: JSON.stringify(body),
  });
  const text = await response.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }
  return { status: response.status, json, text };
}

export async function submitStagingEvidence(options = {}) {
  const inputPath = options.input;
  const parsed = typeof inputPath === 'string'
    ? parseSubmissionInput(inputPath)
    : {
      records: normalizeEvidenceRecords(options.input ?? {}),
      release_id: options.input?.release_id ?? null,
      environment: options.input?.environment ?? null,
      rehearsal_only: options.input?.rehearsal_only,
      created_at: options.input?.created_at ?? null,
      notes: options.input?.notes ?? null,
    };

  const submissionInput = {
    records: parsed.records,
    release_id: options.releaseId ?? parsed.release_id ?? null,
    environment: parsed.environment,
    rehearsal_only: parsed.rehearsal_only,
    created_at: parsed.created_at,
    notes: parsed.notes,
  };

  const validated = validateOperatorAttestedRecords(submissionInput, {
    allowRehearsal: options.allowRehearsal === true,
    allowLocalStaging: options.allowLocalStaging === true,
    profile: options.profile ?? PRODUCTION_PROMOTION_PROFILE,
  });

  const bodies = validated.records.map((record) => ({
    kind: record.kind,
    evidence: record.evidence,
    release_id: record.release_id ?? validated.release_id ?? null,
    ...(record.notes ? { notes: record.notes } : {}),
  }));

  const results = [];
  if (!options.validateOnly && !options.dryRun) {
    for (const body of bodies) {
      const result = await postEvidenceRecord(options.baseUrl, body, options);
      const entry = {
        kind: body.kind,
        release_id: body.release_id ?? null,
        ok: result.status === 201,
        status: result.status,
        response: result.json,
      };
      results.push(entry);
      if (!entry.ok && !options.continueOnError) {
        const detail = result.json?.error ?? result.text ?? `HTTP ${result.status}`;
        throw new Error(`${body.kind} submission failed: ${detail}`);
      }
    }
  }

  const summary = {
    schema_version: 1,
    artifact_type: 'staging_evidence_submission_summary',
    created_at: new Date().toISOString(),
    profile: validated.profile,
    release_id: validated.release_id,
    environment: validated.environment,
    record_count: validated.records.length,
    kinds: validated.records.map((record) => record.kind).sort(),
    validate_only: options.validateOnly === true,
    dry_run: options.dryRun === true,
    submitted: !options.validateOnly && !options.dryRun,
    results,
    caveats: [
      'Submitted via scripts/submit-staging-evidence.mjs for operator-attested staging inventory.',
      'API acceptance records metadata-only evidence; production promotion still requires external signoff.',
    ],
  };

  if (options.out) {
    mkdirSync(path.dirname(options.out), { recursive: true });
    writeFileSync(options.out, `${JSON.stringify(summary, null, 2)}\n`);
  }

  return summary;
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/submit-staging-evidence.mjs --input records.json '
      + '[--base-url https://control-plane] [--release-id rel] [--profile full] '
      + '[--tenant-id ten] [--user-id usr] [--role admin] [--auth-token token] '
      + '[--out output/staging-evidence-submission-summary.json] '
      + '[--validate-only] [--dry-run] [--allow-rehearsal] [--continue-on-error]',
    );
    console.log('');
    console.log('Validates operator-attested release evidence and submits accepted records to POST /v1/production-release-evidence.');
    console.log('Rejects staging-sim and rehearsal/sample markers by default.');
    return 0;
  }

  const summary = await submitStagingEvidence(opts);
  const mode = summary.validate_only
    ? 'validate-only'
    : summary.dry_run
      ? 'dry-run'
      : 'submitted';
  console.log(
    `submit-staging-evidence: ${mode} ${summary.record_count} record(s) `
    + `(profile=${summary.profile}, release_id=${summary.release_id ?? 'none'}, `
    + `environment=${summary.environment ?? 'unspecified'})`,
  );
  if (summary.submitted) {
    const failures = summary.results.filter((entry) => !entry.ok);
    if (failures.length > 0) return 1;
  }
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`submit-staging-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}