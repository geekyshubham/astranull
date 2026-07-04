#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  PRODUCTION_RELEASE_EVIDENCE_KINDS,
  validateProductionReleaseEvidence,
} from '../src/contracts/productionReleaseEvidence.mjs';
import { isNonSubmittableEvidenceRecord } from '../src/contracts/releaseEvidenceProvenance.mjs';
import {
  adaptContractEvidence,
  buildCollectorScriptInput,
  hostedStagingE2eMatrixInputPath,
  localStagingE2eMatrixInputPath,
} from './lib/releaseEvidenceCollectorInputs.mjs';
import { runHostedStagingE2eMatrix } from './hosted-staging-e2e-matrix.mjs';
import { runLocalStagingE2eMatrix } from './local-staging-e2e-matrix.mjs';
import {
  HOSTED_STAGING_ENVIRONMENT,
  HOSTED_STAGING_RELEASE_ID,
  resolveHostedStagingBaseUrl,
} from './lib/hostedStaging.mjs';
import {
  LOCAL_STAGING_ENVIRONMENT,
  LOCAL_STAGING_RELEASE_ID,
} from './lib/localStaging.mjs';
import {
  createStagingE2eMatrixArtifact,
  validateStagingE2eMatrixEvidence,
} from './staging-e2e-matrix-evidence.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const DEFAULT_OUT_DIR = 'output/release-evidence';
const DEFAULT_RELEASE_ID = 'rel-staging-sim-2026-07-03';
const DEFAULT_ENVIRONMENT = 'staging-sim';

const COLLECTOR_SCRIPT_BY_KIND = {
  third_party_security_review: { script: 'scripts/third-party-security-review-evidence.mjs', requiresInput: false },
  migration_apply: { script: 'scripts/migration-apply-evidence.mjs', npmScript: 'migration:apply:evidence', requiresInput: false },
  operator_runbook_exercise: { script: 'scripts/operator-runbook-evidence.mjs', npmScript: 'operator:runbook:evidence', requiresInput: false },
  oidc_prod_auth_preflight: { script: 'scripts/oidc-prod-auth-preflight.mjs', npmScript: 'oidc:prod:preflight', requiresInput: false },
  edge_protection: { script: 'scripts/edge-protection-evidence.mjs', npmScript: 'edge:protection:evidence' },
  agent_sbom_provenance: { script: 'scripts/agent-sbom-provenance-evidence.mjs', npmScript: 'agent:sbom:provenance:evidence', requiresInput: false },
  agent_install_matrix: { script: 'scripts/agent-install-matrix-evidence.mjs', npmScript: 'agent:install:matrix:evidence' },
  agent_mtls_gateway: { script: 'scripts/agent-mtls-gateway-evidence.mjs', npmScript: 'agent:mtls:evidence' },
  agent_trust_key_ceremony: { script: 'scripts/agent-trust-key-ceremony-evidence.mjs', npmScript: 'agent:trust-key:evidence' },
  governed_adapter: { script: 'scripts/governed-adapter-evidence.mjs', npmScript: 'soc:adapter:evidence' },
  provider_approval: { script: 'scripts/provider-approval-evidence.mjs', npmScript: 'soc:provider-approval:evidence' },
  kill_switch_drill: { script: 'scripts/kill-switch-drill-evidence.mjs', npmScript: 'soc:kill-switch:evidence' },
  postgres_concurrency: { script: 'scripts/postgres-concurrency-evidence.mjs', npmScript: 'postgres:concurrency:evidence' },
  dr_restore: { script: 'scripts/dr-restore-evidence.mjs', npmScript: 'dr:restore:evidence' },
  ui_accessibility_matrix: { script: 'scripts/ui-accessibility-matrix-evidence.mjs', npmScript: 'ui:accessibility:matrix:evidence' },
  notification_provider_config: { script: 'scripts/notification-provider-config-evidence.mjs', npmScript: 'notification:provider:evidence' },
  probe_fleet_matrix: { script: 'scripts/probe-fleet-matrix-evidence.mjs', npmScript: 'probe:fleet:matrix:evidence' },
  vector_safety_policy: { script: 'scripts/vector-safety-policy-evidence.mjs', npmScript: 'vector:safety:evidence', requiresInput: false },
  secret_rotation_drill: { script: 'scripts/secret-rotation-drill-evidence.mjs', npmScript: 'secret:rotation:evidence' },
  observability_slo: { script: 'scripts/observability-slo-evidence.mjs', npmScript: 'observability:slo:evidence' },
  support_readiness: { script: 'scripts/support-readiness-evidence.mjs', npmScript: 'support:readiness:evidence' },
  evidence_snapshot_manifest: { script: 'scripts/evidence-snapshot-manifest.mjs', npmScript: 'evidence:snapshot:manifest' },
  postgres_tenant_query_audit: { script: 'scripts/postgres-tenant-query-audit.mjs', npmScript: 'postgres:tenant-query:audit', requiresInput: false },
  rollback_fixforward: { script: 'scripts/rollback-fixforward-evidence.mjs', npmScript: 'rollback:evidence' },
  kms_vault_posture: { script: 'scripts/kms-vault-posture-evidence.mjs', npmScript: 'kms:vault:evidence' },
  control_plane_container_release: { script: 'scripts/container-release-evidence.mjs', npmScript: 'container:evidence' },
  staging_e2e_matrix: { script: 'scripts/staging-e2e-matrix-evidence.mjs', npmScript: 'release:staging-e2e:evidence' },
  compliance_legal_signoff: { script: 'scripts/compliance-legal-signoff-evidence.mjs', npmScript: 'release:compliance-legal:evidence' },
  authorization_custody: { script: 'scripts/authorization-custody-evidence.mjs', npmScript: 'soc:authorization-custody:evidence' },
  placement_confidence_staging: { script: 'scripts/placement-confidence-staging-evidence.mjs', npmScript: 'placement:staging:evidence' },
  gateway_load_abuse: { script: 'scripts/gateway-load-abuse-evidence.mjs', npmScript: 'gateway:load-abuse:evidence' },
};

export const RELEASE_EVIDENCE_COLLECTORS = Object.freeze(
  PRODUCTION_RELEASE_EVIDENCE_KINDS.map((kind) => {
    const entry = COLLECTOR_SCRIPT_BY_KIND[kind];
    if (!entry) throw new Error(`Missing collector script mapping for ${kind}`);
    return Object.freeze({
      kind,
      script: entry.script,
      npmScript: entry.npmScript ?? null,
      requiresInput: entry.requiresInput ?? true,
    });
  }),
);

export function parseArgs(argv = []) {
  const opts = {
    outDir: DEFAULT_OUT_DIR,
    releaseId: DEFAULT_RELEASE_ID,
    environment: DEFAULT_ENVIRONMENT,
    dryRun: false,
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
    if (arg === '--out-dir') opts.outDir = next();
    else if (arg === '--release-id') opts.releaseId = next();
    else if (arg === '--environment') opts.environment = next();
    else if (arg === '--dry-run') opts.dryRun = true;
    else if (arg === '--continue-on-error') opts.continueOnError = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return opts;
}

export function evidenceUriForKind(kind, environment = DEFAULT_ENVIRONMENT) {
  return `evidence://release-evidence/${kind}/${environment}`;
}

export function buildCollectionContext(options = {}) {
  const outDir = path.resolve(REPO_ROOT, options.outDir ?? DEFAULT_OUT_DIR);
  const environment = options.environment
    ?? process.env.ASTRANULL_LOCAL_STAGING_ENVIRONMENT
    ?? DEFAULT_ENVIRONMENT;
  const releaseId = options.releaseId
    ?? process.env.ASTRANULL_LOCAL_STAGING_RELEASE_ID
    ?? (environment === LOCAL_STAGING_ENVIRONMENT
      ? LOCAL_STAGING_RELEASE_ID
      : environment === HOSTED_STAGING_ENVIRONMENT
        ? HOSTED_STAGING_RELEASE_ID
        : DEFAULT_RELEASE_ID);
  return {
    repoRoot: REPO_ROOT,
    outDir,
    inputsDir: path.join(outDir, 'inputs'),
    releaseId,
    environment,
    createdAt: options.createdAt ?? new Date().toISOString(),
    dryRun: options.dryRun === true,
    continueOnError: options.continueOnError === true,
    evidenceUri: (kind) => evidenceUriForKind(kind, environment),
  };
}

export function artifactPathForKind(kind, context) {
  return path.join(context.outDir, `${kind}.json`);
}

export function inputPathForKind(kind, context) {
  return path.join(context.inputsDir, `${kind}.json`);
}

export function productionOidcPreflightEnv() {
  return {
    ...process.env,
    NODE_ENV: 'production',
    ASTRANULL_AUTH_MODE: 'oidc-jwt',
    ASTRANULL_OIDC_ISSUER: 'https://idp.example/oauth2/default',
    ASTRANULL_OIDC_AUDIENCE: 'astranull-api',
    ASTRANULL_OIDC_JWKS_URL: 'https://idp.example/oauth2/default/v1/keys',
    ASTRANULL_SECRET_ENCRYPTION_KEY: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    ASTRANULL_DATABASE_URL: 'postgresql://preflight:secret@db.example:5432/astranull',
    ASTRANULL_PROBE_WORKER_SECRET: 'preflight-probe-worker-secret-32-chars!!',
  };
}

export function collectorProcessEnv(kind) {
  if (kind === 'oidc_prod_auth_preflight') {
    return productionOidcPreflightEnv();
  }
  return process.env;
}

export function buildCollectorCommand(collector, context) {
  const scriptPath = path.resolve(REPO_ROOT, collector.script);
  const artifactPath = artifactPathForKind(collector.kind, context);
  const { input, extraArgs = [] } = buildCollectorScriptInput(collector.kind, {
    ...context,
    outDir: context.outDir,
  });

  const args = [scriptPath];
  if (input !== null && input !== undefined) {
    const inputPath = inputPathForKind(collector.kind, context);
    args.push('--input', inputPath);
  }
  args.push('--out', artifactPath);
  if (['migration_apply', 'operator_runbook_exercise'].includes(collector.kind)) {
    args.push('--environment', context.environment, '--release-id', context.releaseId);
  } else if (collector.kind === 'third_party_security_review') {
    args.push('--release-id', context.releaseId);
  }
  args.push(...extraArgs);
  return { command: process.execPath, args, artifactPath, input };
}

export function extractProductionReleaseRecord(kind, artifact, context) {
  if (artifact?.production_release_evidence?.kind === kind) {
    return {
      kind,
      evidence: artifact.production_release_evidence.evidence,
      status: 'accepted',
      release_id: context.releaseId,
    };
  }

  if (kind === 'governed_adapter' && artifact?.evidence) {
    return {
      kind,
      evidence: artifact.evidence,
      status: 'accepted',
      release_id: context.releaseId,
    };
  }

  if (kind === 'oidc_prod_auth_preflight') {
    return {
      kind,
      evidence: {
        created_at: artifact.created_at,
        node_env: artifact.node_env,
        ok: artifact.ok,
        checks: artifact.checks,
        auth_posture: artifact.auth_posture,
        evidence_uri: context.evidenceUri(kind),
      },
      status: 'accepted',
      release_id: context.releaseId,
    };
  }

  if (kind === 'vector_safety_policy') {
    return {
      kind,
      evidence: {
        schema_version: artifact.schema_version,
        artifact_type: artifact.artifact_type,
        created_at: artifact.created_at,
        validation: artifact.validation,
        customer_runnable_policies: artifact.customer_runnable_policies,
        soc_request_only_markers: artifact.soc_request_only_markers,
        evidence_uri: context.evidenceUri(kind),
      },
      status: 'accepted',
      release_id: context.releaseId,
    };
  }

  if (kind === 'postgres_tenant_query_audit') {
    return {
      kind,
      evidence: {
        schema_version: artifact.schema_version,
        artifact_type: artifact.artifact_type,
        scanned_files: artifact.scanned_files,
        finding_count: artifact.finding_count,
        findings: artifact.findings,
        evidence_uri: artifact.evidence_uri ?? context.evidenceUri(kind),
      },
      status: 'accepted',
      release_id: context.releaseId,
    };
  }

  if (kind === 'kill_switch_drill') {
    return {
      kind,
      evidence: {
        created_at: artifact.created_at,
        drill_id: artifact.drill_id,
        tenant_id: artifact.tenant_id,
        response_latency_ms: artifact.response_latency_ms,
        latency_ok: artifact.latency_ok,
        transcript: artifact.transcript,
        evidence_uri: context.evidenceUri(kind),
      },
      status: 'accepted',
      release_id: context.releaseId,
    };
  }

  if (kind === 'agent_sbom_provenance') {
    return {
      kind,
      evidence: {
        created_at: artifact.created_at,
        package_format: artifact.package_format,
        package: {
          name: artifact.package?.name ?? 'astranull-agent',
          sha256: artifact.package?.sha256,
          size: artifact.package?.size,
        },
        sbom: {
          sha256: artifact.sbom?.sha256,
          size: artifact.sbom?.size,
          summary: artifact.sbom?.summary,
        },
        provenance: {
          sha256: artifact.provenance?.sha256,
          size: artifact.provenance?.size,
          summary: artifact.provenance?.summary,
        },
        evidence_uri: context.evidenceUri(kind),
      },
      status: 'accepted',
      release_id: context.releaseId,
    };
  }

  if (kind === 'agent_install_matrix') {
    return {
      kind,
      evidence: {
        created_at: artifact.created_at,
        matrix_id: artifact.matrix_id,
        overall_status: artifact.overall_status,
        rows: artifact.rows,
        evidence_uri: context.evidenceUri(kind),
      },
      status: 'accepted',
      release_id: context.releaseId,
    };
  }

  if (kind === 'ui_accessibility_matrix') {
    return {
      kind,
      evidence: {
        created_at: artifact.created_at,
        runs: artifact.runs,
        evidence_uri: context.evidenceUri(kind),
      },
      status: 'accepted',
      release_id: context.releaseId,
    };
  }

  return {
    kind,
    evidence: adaptContractEvidence(kind, context),
    status: 'accepted',
    release_id: context.releaseId,
  };
}

export function validateCollectedRecord(record, options = {}) {
  const validation = validateProductionReleaseEvidence(record.kind, record.evidence);
  if (!validation.ok) {
    const problems = [
      ...validation.missing_fields.map((field) => `missing:${field}`),
      ...validation.forbidden_fields.map((field) => `forbidden:${field}`),
      ...(validation.invalid_fields ?? []).map((field) => `invalid:${field.field ?? field}`),
    ];
    throw new Error(`${record.kind} record failed contract validation (${problems.join(', ')})`);
  }
  if (record.rehearsal_only === true) {
    throw new Error(`${record.kind} record must not include rehearsal_only=true`);
  }
  if (options.requireSubmittable === true && isNonSubmittableEvidenceRecord(record)) {
    throw new Error(`${record.kind} record is non-submittable dry-run or draft evidence`);
  }
  return validation;
}

export function buildRecordsPayload(records, context) {
  return {
    schema_version: 1,
    artifact_type: 'production_release_evidence_records',
    created_at: context.createdAt,
    release_id: context.releaseId,
    environment: context.environment,
    dry_run: context.dryRun === true,
    submittable: context.dryRun !== true,
    records,
    caveats: [
      'Collected via scripts/collect-release-evidence.mjs invoking metadata-only evidence CLIs.',
      context.dryRun === true
        ? 'Dry-run records are contract-shaped previews only; they are non-submittable and cannot satisfy production readiness.'
        : 'Staging-sim inventory for local gap audit only; submit operator-attested staging records via scripts/submit-staging-evidence.mjs.',
      'External staging, security, SOC, and legal signoff gates remain required beyond this bundle.',
    ],
  };
}

export function runCollector(collector, context, options = {}) {
  const runCommand = options.runCommand ?? defaultRunCommand;
  const { command, args, artifactPath, input } = buildCollectorCommand(collector, context);

  if (input !== null && input !== undefined) {
    mkdirSync(context.inputsDir, { recursive: true });
    writeFileSync(inputPathForKind(collector.kind, context), `${JSON.stringify(input, null, 2)}\n`);
  }

  if (context.dryRun) {
    const dryArtifact = collector.kind === 'staging_e2e_matrix' && input
      ? createStagingE2eMatrixArtifact({
        evidence: input,
        validation: validateStagingE2eMatrixEvidence(input, { releaseId: context.releaseId }),
        releaseId: context.releaseId,
        createdAt: context.createdAt,
      })
      : {
        schema_version: 1,
        artifact_type: `${collector.kind}_dry_run`,
        created_at: context.createdAt,
        dry_run: true,
        production_release_evidence: {
          kind: collector.kind,
          evidence: adaptContractEvidence(collector.kind, context),
        },
      };
    mkdirSync(path.dirname(artifactPath), { recursive: true });
    writeFileSync(artifactPath, `${JSON.stringify(dryArtifact, null, 2)}\n`);
    const record = extractProductionReleaseRecord(collector.kind, dryArtifact, context);
    record.status = 'draft';
    record.submittable = false;
    record.dry_run = true;
    record.collector_dry_run = true;
    validateCollectedRecord(record);
    return { kind: collector.kind, ok: true, artifactPath, dryRun: true, record };
  }

  const result = runCommand(command, args, {
    cwd: REPO_ROOT,
    env: collectorProcessEnv(collector.kind),
  });
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || '').trim();
    const error = new Error(
      `${collector.kind} collector failed (exit ${result.status})${detail ? `: ${detail}` : ''}`,
    );
    if (!context.continueOnError) throw error;
    return { kind: collector.kind, ok: false, artifactPath, error: error.message };
  }

  const artifact = JSON.parse(readFileSync(artifactPath, 'utf8'));
  const record = extractProductionReleaseRecord(collector.kind, artifact, context);
  validateCollectedRecord(record);
  return { kind: collector.kind, ok: true, artifactPath, record };
}

function defaultRunCommand(command, args, options) {
  return spawnSync(command, args, {
    cwd: options.cwd,
    env: options.env ?? process.env,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

async function ensureLocalStagingE2eMatrix(context, options = {}) {
  if (context.environment !== LOCAL_STAGING_ENVIRONMENT) return null;
  if (context.dryRun === true || options.skipLocalStagingE2e === true) return null;
  const inputPath = localStagingE2eMatrixInputPath(context);
  if (existsSync(inputPath) && options.refreshLocalStagingE2e !== true) {
    return inputPath;
  }
  const baseUrl = process.env.ASTRANULL_LOCAL_STAGING_BASE_URL ?? 'http://127.0.0.1:3000';
  const result = await runLocalStagingE2eMatrix({
    baseUrl,
    out: inputPath,
    artifactOut: artifactPathForKind('staging_e2e_matrix', context),
  });
  if (!result.validation.ok) {
    throw new Error(
      `local-staging E2E matrix incomplete (overall_status=${result.artifact.overall_status})`,
    );
  }
  return inputPath;
}

async function ensureHostedStagingE2eMatrix(context, options = {}) {
  if (context.environment !== HOSTED_STAGING_ENVIRONMENT) return null;
  if (context.dryRun === true || options.skipHostedStagingE2e === true) return null;
  const inputPath = hostedStagingE2eMatrixInputPath(context);
  if (existsSync(inputPath) && options.refreshHostedStagingE2e !== true) {
    return inputPath;
  }
  const baseUrl = resolveHostedStagingBaseUrl();
  if (!baseUrl) {
    throw new Error('ASTRANULL_HOSTED_STAGING_BASE_URL is required to collect hosted staging E2E evidence');
  }
  const result = await runHostedStagingE2eMatrix({
    baseUrl,
    out: inputPath,
    artifactOut: artifactPathForKind('staging_e2e_matrix', context),
  });
  if (!result.validation.ok) {
    throw new Error(
      `hosted-staging E2E matrix incomplete (overall_status=${result.artifact.overall_status})`,
    );
  }
  return inputPath;
}

export async function collectReleaseEvidence(options = {}) {
  const context = buildCollectionContext(options);
  mkdirSync(context.outDir, { recursive: true });
  await ensureLocalStagingE2eMatrix(context, options);
  await ensureHostedStagingE2eMatrix(context, options);

  const results = [];
  const records = [];

  for (const collector of RELEASE_EVIDENCE_COLLECTORS) {
    const result = runCollector(collector, context, options);
    results.push(result);
    if (result.ok && result.record) {
      records.push(result.record);
    }
  }

  const recordsPath = path.join(context.outDir, 'records.json');
  const payload = buildRecordsPayload(records, context);
  writeFileSync(recordsPath, `${JSON.stringify(payload, null, 2)}\n`);

  const summary = {
    outDir: context.outDir,
    recordsPath,
    releaseId: context.releaseId,
    environment: context.environment,
    dryRun: context.dryRun,
    kindsRequested: RELEASE_EVIDENCE_COLLECTORS.length,
    kindsCollected: records.length,
    kindsFailed: results.filter((entry) => !entry.ok).length,
    kinds: records.map((entry) => entry.kind).sort(),
    failures: results.filter((entry) => !entry.ok).map((entry) => ({
      kind: entry.kind,
      error: entry.error,
    })),
    results,
    records,
    payload,
  };

  writeFileSync(
    path.join(context.outDir, 'collection-summary.json'),
    `${JSON.stringify({
      schema_version: 1,
      artifact_type: 'release_evidence_collection_summary',
      created_at: context.createdAt,
      release_id: context.releaseId,
      environment: context.environment,
      dry_run: context.dryRun,
      kinds_requested: summary.kindsRequested,
      kinds_collected: summary.kindsCollected,
      kinds_failed: summary.kindsFailed,
      kinds: summary.kinds,
      failures: summary.failures,
      records_path: recordsPath,
    }, null, 2)}\n`,
  );

  if (summary.kindsFailed > 0 && !context.continueOnError) {
    throw new Error(
      `release evidence collection incomplete (${summary.kindsFailed} failure(s)); see ${path.join(context.outDir, 'collection-summary.json')}`,
    );
  }

  return summary;
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/collect-release-evidence.mjs '
      + `[--out-dir ${DEFAULT_OUT_DIR}] [--release-id rel] [--environment staging-sim] `
      + '[--dry-run] [--continue-on-error]',
    );
    console.log('');
    console.log(`Collects all ${PRODUCTION_RELEASE_EVIDENCE_KINDS.length} production release evidence kinds `
      + 'into output/release-evidence/records.json for gap audit.');
    return 0;
  }

  const summary = await collectReleaseEvidence(opts);
  console.log(
    `collect-release-evidence: wrote ${summary.recordsPath} `
    + `(${summary.kindsCollected}/${summary.kindsRequested} kind(s), release_id=${summary.releaseId}, `
    + `environment=${summary.environment}${summary.dryRun ? ', dry-run' : ''})`,
  );
  return summary.kindsCollected === summary.kindsRequested ? 0 : 1;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`collect-release-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}
