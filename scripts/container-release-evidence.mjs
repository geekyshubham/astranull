#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateProductionReleaseEvidence } from '../src/contracts/productionReleaseEvidence.mjs';
import { redactObject, redactString } from '../src/lib/redact.mjs';

const DEFAULT_IMAGE = 'astranull-control-plane:local';
const DEFAULT_OUT = 'output/container-release-evidence.json';
const ALLOWED_SCANNERS = new Set(['none', 'trivy', 'grype']);

export const CONTROL_PLANE_CONTAINER_RELEASE_KIND = 'control_plane_container_release';

const CONTAINER_RELEASE_FORBIDDEN_KEYS = new Set([
  'api_key',
  'apikey',
  'attachment',
  'attachments',
  'auth',
  'auth_config',
  'auths',
  'authorization',
  'body',
  'config_json',
  'connection_string',
  'credential',
  'credentials',
  'database_url',
  'docker_config',
  'dockerconfig',
  'dockerconfigjson',
  'headers',
  'identitytoken',
  'key_file',
  'key_material',
  'kubeconfig',
  'log',
  'logs',
  'password',
  'payload',
  'private_key',
  'raw_body',
  'raw_dump',
  'raw_headers',
  'raw_log',
  'raw_logs',
  'raw_scan',
  'raw_scan_log',
  'refreshtoken',
  'registry_credential',
  'registry_credentials',
  'registry_token',
  'scan_log',
  'scan_logs',
  'scan_output',
  'secret',
  'token',
  'vulnerabilities',
]);

const REGISTRY_SECRET_STRING_PATTERNS = [
  { pattern: /"auths"\s*:\s*\{/, reason: 'docker_config_auths' },
  { pattern: /"auth"\s*:\s*"[A-Za-z0-9+/=]{12,}"/, reason: 'registry_auth_blob' },
  { pattern: /registry\.[a-z0-9.-]+\/.*:(?:[A-Za-z0-9+/=]{8,}|[^\s@]+@[^\s/]+)/i, reason: 'registry_url_with_secret' },
];

function normalizeKey(key) {
  return key
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function collectContainerForbiddenFields(value, fieldPath = '') {
  if (value === null || value === undefined || typeof value !== 'object') return [];
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectContainerForbiddenFields(entry, `${fieldPath}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = fieldPath ? `${fieldPath}.${key}` : key;
    const normalized = normalizeKey(key);
    if (isForbiddenKey(key)) {
      findings.push(keyPath);
    }
    findings.push(...collectContainerForbiddenFields(nested, keyPath));
  }
  return findings;
}

function isForbiddenKey(key) {
  const normalized = normalizeKey(key);
  return (
    CONTAINER_RELEASE_FORBIDDEN_KEYS.has(normalized)
    || normalized.startsWith('raw_')
    || normalized.includes('registry_credential')
  );
}

function sanitizeControlPlaneContainerReleaseEvidence(evidence) {
  if (evidence === null || evidence === undefined || typeof evidence !== 'object') {
    return evidence;
  }
  if (Array.isArray(evidence)) {
    return evidence.map((entry) => sanitizeControlPlaneContainerReleaseEvidence(entry));
  }
  const out = {};
  for (const [key, nested] of Object.entries(evidence)) {
    if (isForbiddenKey(key)) continue;
    out[key] = sanitizeControlPlaneContainerReleaseEvidence(nested);
  }
  return out;
}

function collectForbiddenStringPatterns(value, fieldPath = '') {
  if (value === null || value === undefined) return [];
  if (typeof value === 'string') {
    const findings = [];
    for (const { pattern, reason } of REGISTRY_SECRET_STRING_PATTERNS) {
      if (pattern.test(value)) {
        findings.push(`${fieldPath}:${reason}`);
      }
      pattern.lastIndex = 0;
    }
    return findings;
  }
  if (Array.isArray(value)) {
    return value.flatMap((entry, index) =>
      collectForbiddenStringPatterns(entry, `${fieldPath}[${index}]`),
    );
  }
  if (typeof value === 'object') {
    return Object.entries(value).flatMap(([key, nested]) =>
      collectForbiddenStringPatterns(nested, fieldPath ? `${fieldPath}.${key}` : key),
    );
  }
  return [];
}

export function parseArgs(argv = []) {
  const opts = {
    image: DEFAULT_IMAGE,
    dockerfile: 'Dockerfile',
    context: '.',
    out: DEFAULT_OUT,
    scanner: 'none',
    promotionTarget: null,
    commit: null,
    requireScan: false,
    input: null,
    releaseId: null,
    validateOnly: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`Missing value for ${arg}`);
      return argv[i];
    };
    if (arg === '--image') opts.image = next();
    else if (arg === '--dockerfile') opts.dockerfile = next();
    else if (arg === '--context') opts.context = next();
    else if (arg === '--out') opts.out = next();
    else if (arg === '--scanner') opts.scanner = next();
    else if (arg === '--promotion-target') opts.promotionTarget = next();
    else if (arg === '--commit') opts.commit = next();
    else if (arg === '--require-scan') opts.requireScan = true;
    else if (arg === '--input') opts.input = next();
    else if (arg === '--release-id') opts.releaseId = next();
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!ALLOWED_SCANNERS.has(opts.scanner)) {
    throw new Error(`Invalid scanner "${opts.scanner}". Allowed: ${[...ALLOWED_SCANNERS].join(', ')}`);
  }
  if (opts.requireScan && opts.scanner === 'none') {
    throw new Error('--require-scan requires --scanner trivy or --scanner grype');
  }
  return opts;
}

export function normalizeControlPlaneContainerReleaseInput(parsed) {
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('container-release-evidence: input must be a JSON object');
  }
  if (parsed.production_release_evidence?.evidence) {
    return parsed.production_release_evidence.evidence;
  }
  if (parsed.kind === CONTROL_PLANE_CONTAINER_RELEASE_KIND && parsed.evidence) {
    return parsed.evidence;
  }
  return parsed;
}

/**
 * @param {unknown} evidence
 */
export function validateControlPlaneContainerReleaseEvidence(evidence) {
  const contract = validateProductionReleaseEvidence(CONTROL_PLANE_CONTAINER_RELEASE_KIND, evidence);
  const forbidden_fields = [
    ...new Set([
      ...contract.forbidden_fields,
      ...collectContainerForbiddenFields(evidence),
      ...collectForbiddenStringPatterns(evidence),
    ]),
  ].sort();
  const ok =
    contract.invalid_kind === null
    && contract.missing_fields.length === 0
    && forbidden_fields.length === 0;
  return {
    ok,
    invalid_kind: contract.invalid_kind,
    missing_fields: contract.missing_fields,
    forbidden_fields,
    contract_ok: contract.ok,
  };
}

/**
 * @param {{ evidence: Record<string, unknown>, validation: ReturnType<typeof validateControlPlaneContainerReleaseEvidence>, releaseId?: string | null, notes?: string }} input
 */
export function buildProductionReleaseEvidenceWrapper(input) {
  const { evidence, validation, releaseId, notes } = input;
  const redactedEvidence = redactObject(sanitizeControlPlaneContainerReleaseEvidence(evidence));
  const wrapper = {
    kind: CONTROL_PLANE_CONTAINER_RELEASE_KIND,
    evidence: redactedEvidence,
  };
  const resolvedReleaseId = releaseId ?? redactedEvidence.release_id ?? null;
  if (resolvedReleaseId) {
    wrapper.release_id = String(resolvedReleaseId);
  }
  if (notes) {
    wrapper.notes = redactString(String(notes));
  }
  return {
    wrapper,
    validation,
  };
}

/**
 * @param {{ evidence: Record<string, unknown>, validation: ReturnType<typeof validateControlPlaneContainerReleaseEvidence>, releaseId?: string | null, notes?: string, createdAt?: string }} input
 */
export function createControlPlaneContainerReleaseArtifact(input) {
  const { evidence, validation, releaseId, notes, createdAt } = input;
  const { wrapper } = buildProductionReleaseEvidenceWrapper({
    evidence,
    validation,
    releaseId,
    notes,
  });
  return {
    schema_version: 1,
    artifact_type: 'control_plane_container_release_evidence',
    created_at: createdAt ?? evidence.created_at ?? new Date().toISOString(),
    validation: {
      ok: validation.ok,
      missing_fields: validation.missing_fields,
      forbidden_fields: validation.forbidden_fields,
      contract_ok: validation.contract_ok,
    },
    production_release_evidence: wrapper,
    caveats: [
      'Metadata-only control-plane container release evidence; no raw scan logs, registry credentials, Docker config auth, private keys, or payloads.',
      'Image digest, signing, promotion, and rollback references must be recorded in immutable custody outside this validator.',
    ],
  };
}

export function buildDockerBuildCommand(opts) {
  return {
    cmd: 'docker',
    args: [
      'build',
      '--pull',
      '--label',
      'org.opencontainers.image.title=AstraNull Control Plane',
      '-f',
      opts.dockerfile,
      '-t',
      opts.image,
      opts.context,
    ],
  };
}

export function buildDockerInspectCommand(opts) {
  return {
    cmd: 'docker',
    args: ['image', 'inspect', opts.image, '--format', '{{json .}}'],
  };
}

export function buildScannerCommand(opts) {
  if (opts.scanner === 'none') return null;
  if (opts.scanner === 'trivy') {
    return { cmd: 'trivy', args: ['image', '--format', 'json', '--exit-code', '1', opts.image] };
  }
  return { cmd: 'grype', args: [opts.image, '-o', 'json', '--fail-on', 'high'] };
}

function safeString(value) {
  if (value == null) return null;
  return String(value);
}

export function createContainerEvidenceManifest(input) {
  return {
    schema_version: 1,
    artifact_type: 'control_plane_container',
    created_at: input.createdAt ?? new Date().toISOString(),
    image: safeString(input.image),
    dockerfile: safeString(input.dockerfile),
    context: safeString(input.context),
    image_id: safeString(input.imageId),
    repo_digests: Array.isArray(input.repoDigests) ? input.repoDigests.map(String) : [],
    scanner: input.scanner ?? 'none',
    scan_status: input.scanStatus ?? 'not_run',
    scan_summary: input.scanSummary ?? null,
    promotion_target: input.promotionTarget ?? null,
    commit: input.commit ?? null,
    caveats: [
      'Manifest records local build/inspect/scan evidence only.',
      'Production promotion still requires registry digest, signed release evidence, runtime secrets, Postgres acceptance, and staging signoff.',
    ],
  };
}

function readMetadataInput(inputPath) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(inputPath, 'utf8'));
  } catch {
    throw new Error(`container-release-evidence: input is not valid JSON: ${inputPath}`);
  }
  return normalizeControlPlaneContainerReleaseInput(parsed);
}

function runCommand(command, label) {
  const result = spawnSync(command.cmd, command.args, {
    encoding: 'utf8',
    maxBuffer: 10 * 1024 * 1024,
  });
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || '').trim();
    throw new Error(`${label} failed${detail ? `: ${detail}` : ''}`);
  }
  return result.stdout ?? '';
}

function parseInspectJson(stdout) {
  const parsed = JSON.parse(stdout);
  return Array.isArray(parsed) ? parsed[0] : parsed;
}

async function runMetadataEvidenceWorkflow(opts) {
  const evidence = readMetadataInput(opts.input);
  const validation = validateControlPlaneContainerReleaseEvidence(evidence);
  const artifact = createControlPlaneContainerReleaseArtifact({
    evidence,
    validation,
    releaseId: opts.releaseId,
    notes: typeof evidence.notes === 'string' ? evidence.notes : undefined,
  });

  if (opts.validateOnly) {
    console.log(
      `container-release-evidence: ${validation.ok ? 'ok' : 'failed'} (release_id=${artifact.production_release_evidence.release_id ?? 'none'})`,
    );
    return validation.ok ? 0 : 1;
  }

  if (!validation.ok) {
    const problems = [
      ...validation.missing_fields.map((field) => `missing:${field}`),
      ...validation.forbidden_fields.map((field) => `forbidden:${field}`),
    ];
    throw new Error(`container-release-evidence: invalid metadata (${problems.join(', ')})`);
  }

  mkdirSync(path.dirname(path.resolve(opts.out)), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(artifact, null, 2)}\n`);
  console.log(`container-release-evidence: wrote ${opts.out}`);
  return 0;
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(`Usage: node scripts/container-release-evidence.mjs [--input evidence.json] [--out file] [--release-id id] [--validate-only]
       node scripts/container-release-evidence.mjs [--image name] [--scanner none|trivy|grype] [--require-scan] [--out file]

Metadata mode (--input) validates production release evidence for control_plane_container_release without Docker or registry access.
Local mode builds/inspects/scans an image and writes a safe local manifest only.`);
    return 0;
  }

  if (opts.input) {
    return runMetadataEvidenceWorkflow(opts);
  }

  runCommand(buildDockerBuildCommand(opts), 'docker build');
  const inspect = parseInspectJson(runCommand(buildDockerInspectCommand(opts), 'docker image inspect'));

  let scanStatus = 'not_run';
  let scanSummary = null;
  const scannerCommand = buildScannerCommand(opts);
  if (scannerCommand) {
    try {
      const scanOut = runCommand(scannerCommand, `${opts.scanner} scan`);
      scanStatus = 'passed';
      scanSummary = scanOut ? { output_bytes: Buffer.byteLength(scanOut, 'utf8') } : null;
    } catch (err) {
      scanStatus = 'failed';
      scanSummary = { error: err.message };
      if (opts.requireScan) throw err;
    }
  }

  const manifest = createContainerEvidenceManifest({
    ...opts,
    imageId: inspect.Id,
    repoDigests: inspect.RepoDigests ?? [],
    scanStatus,
    scanSummary,
  });
  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`container-release-evidence: wrote ${opts.out}`);
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`container-release-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}