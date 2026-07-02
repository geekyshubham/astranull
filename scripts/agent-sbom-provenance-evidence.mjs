#!/usr/bin/env node
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactObject } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/agent-sbom-provenance-evidence.json';
const ALLOWED_FORMATS = new Set(['tar', 'deb', 'rpm', 'container', 'generic']);

const SECRET_PATTERNS = [
  /ast_v1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}/,
  /svc_v1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}/,
  /agc_v1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}/,
  /ast_[A-Za-z0-9_-]{8,}/,
  /svc_[A-Za-z0-9_-]{8,}/,
  /agc_[A-Za-z0-9_-]{8,}/,
  /Bearer\s+[A-Za-z0-9._-]+/i,
  /sk-[A-Za-z0-9]{16,}/,
  /postgres:\/\/[^\s"']+/i,
  /mongodb(\+srv)?:\/\/[^\s"']+/i,
  /AKIA[0-9A-Z]{16}/,
];

const PATH_TRAVERSAL = /(?:^|[\\/])\.\.(?:[\\/]|$)|\0/;

export function parseArgs(argv = []) {
  const opts = {
    package: null,
    sbom: null,
    provenance: null,
    out: DEFAULT_OUT,
    format: 'generic',
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`Missing value for ${arg}`);
      return argv[i];
    };
    if (arg === '--package') opts.package = next();
    else if (arg === '--sbom') opts.sbom = next();
    else if (arg === '--provenance') opts.provenance = next();
    else if (arg === '--out') opts.out = next();
    else if (arg === '--format') opts.format = next();
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!opts.help) {
    if (!opts.package) throw new Error('--package is required');
    if (!opts.sbom) throw new Error('--sbom is required');
    if (!opts.provenance) throw new Error('--provenance is required');
    if (!ALLOWED_FORMATS.has(opts.format)) {
      throw new Error(`Invalid format "${opts.format}". Allowed: ${[...ALLOWED_FORMATS].join(', ')}`);
    }
  }
  return opts;
}

export function sha256Buffer(data) {
  return createHash('sha256').update(data).digest('hex');
}

export function digestFileArtifact(filePath, label = 'file') {
  if (!filePath || typeof filePath !== 'string') {
    throw new Error(`${label} path is required`);
  }
  if (!fs.existsSync(filePath)) {
    throw new Error(`${label} not found: ${filePath}`);
  }
  const stat = statSync(filePath);
  if (!stat.isFile()) {
    throw new Error(`${label} must be a regular file: ${filePath}`);
  }
  if (stat.size === 0) {
    throw new Error(`${label} is empty: ${filePath}`);
  }
  const bytes = readFileSync(filePath);
  return {
    path: filePath,
    sha256: sha256Buffer(bytes),
    size: stat.size,
  };
}

export function assertSafePackageReference(packagePath) {
  if (!packagePath || typeof packagePath !== 'string') {
    throw new Error('package path is required');
  }
  if (PATH_TRAVERSAL.test(packagePath)) {
    throw new Error(`Unsafe package path: ${packagePath}`);
  }
  const base = path.basename(packagePath);
  if (!base || base === '.' || base === '..') {
    throw new Error(`Unsafe package name: ${base || packagePath}`);
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(base)) {
    throw new Error(`Unsafe package name: ${base}`);
  }
  return base;
}

export function detectEvidenceSecrets(text, label = 'evidence') {
  if (typeof text !== 'string') return [];
  const hits = [];
  for (const pattern of SECRET_PATTERNS) {
    if (pattern.test(text)) hits.push(pattern.source);
    pattern.lastIndex = 0;
  }
  if (hits.length > 0) {
    throw new Error(`${label} contains forbidden secret or token pattern`);
  }
  return hits;
}

export function parseJsonFile(filePath, label) {
  const raw = readFileSync(filePath, 'utf8');
  detectEvidenceSecrets(raw, label);
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error(`${label} must be valid JSON: ${filePath}`);
  }
}

export function validateSbomDocument(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    throw new Error('SBOM must be a JSON object');
  }
  const cyclone = doc.bomFormat === 'CycloneDX' && typeof doc.specVersion === 'string';
  const spdx = typeof doc.spdxVersion === 'string' || (typeof doc.SPDXID === 'string' && doc.SPDXID.startsWith('SPDX'));
  if (!cyclone && !spdx) {
    throw new Error('SBOM must include a recognizable CycloneDX or SPDX marker');
  }
  return {
    sbom_format: cyclone ? 'cyclonedx' : 'spdx',
    spec_version: cyclone ? String(doc.specVersion) : String(doc.spdxVersion ?? ''),
    serial_number: doc.serialNumber ? String(doc.serialNumber) : null,
    spdx_id: doc.SPDXID ? String(doc.SPDXID) : null,
    component_count: Array.isArray(doc.components)
      ? doc.components.length
      : Array.isArray(doc.packages)
        ? doc.packages.length
        : 0,
  };
}

export function validateProvenanceDocument(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    throw new Error('Provenance must be a JSON object');
  }
  const hasSubject = doc.subject != null;
  const hasMaterials = Array.isArray(doc.materials);
  const hasPredicate = doc.predicate != null || typeof doc.predicateType === 'string';
  if (!hasSubject || !hasMaterials || !hasPredicate) {
    throw new Error('Provenance must include subject, materials, and predicate metadata');
  }
  const subjects = Array.isArray(doc.subject) ? doc.subject : [doc.subject];
  return {
    predicate_type: doc.predicateType ? String(doc.predicateType) : null,
    subject_count: subjects.length,
    materials_count: doc.materials.length,
    statement_type: doc._type ? String(doc._type) : null,
  };
}

export function createAgentSbomProvenanceManifest(input) {
  return {
    schema_version: 1,
    artifact_type: 'agent_sbom_provenance',
    created_at: input.createdAt ?? new Date().toISOString(),
    package_format: input.format ?? 'generic',
    package: {
      name: input.packageName ?? null,
      path: input.package?.path ?? null,
      sha256: input.package?.sha256 ?? null,
      size: input.package?.size ?? null,
    },
    sbom: {
      path: input.sbom?.path ?? null,
      sha256: input.sbom?.sha256 ?? null,
      size: input.sbom?.size ?? null,
      summary: redactObject(input.sbomSummary ?? {}),
    },
    provenance: {
      path: input.provenance?.path ?? null,
      sha256: input.provenance?.sha256 ?? null,
      size: input.provenance?.size ?? null,
      summary: redactObject(input.provenanceSummary ?? {}),
    },
    caveats: [
      'Manifest records metadata-only SBOM and provenance evidence for agent package promotion review.',
      'This utility does not execute packages, install artifacts, or call external registries.',
      'Production promotion still requires package signing, hosted artifact custody, distro/Kubernetes install matrix validation, and staging signoff.',
    ],
  };
}

export function collectAgentSbomProvenanceEvidence(opts) {
  const packageName = assertSafePackageReference(opts.package);
  const packageDigest = digestFileArtifact(opts.package, 'package');
  const sbomDigest = digestFileArtifact(opts.sbom, 'SBOM');
  const provenanceDigest = digestFileArtifact(opts.provenance, 'provenance');

  const sbomDoc = parseJsonFile(opts.sbom, 'SBOM');
  const provenanceDoc = parseJsonFile(opts.provenance, 'provenance');
  const sbomSummary = validateSbomDocument(sbomDoc);
  const provenanceSummary = validateProvenanceDocument(provenanceDoc);

  return createAgentSbomProvenanceManifest({
    createdAt: opts.createdAt,
    format: opts.format,
    packageName,
    package: packageDigest,
    sbom: sbomDigest,
    provenance: provenanceDigest,
    sbomSummary,
    provenanceSummary,
  });
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/agent-sbom-provenance-evidence.mjs --package <path> --sbom <path> --provenance <path> [--format tar|deb|rpm|container|generic] [--out file]',
    );
    return 0;
  }

  const manifest = collectAgentSbomProvenanceEvidence(opts);
  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`agent-sbom-provenance-evidence: wrote ${opts.out}`);
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`agent-sbom-provenance-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}