#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256CanonicalJson } from '../src/lib/custody.mjs';
import { verifyCustodyManifestSignature } from '../src/lib/evidenceSigning.mjs';
import { redactObject, redactString } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/evidence-snapshot-manifest.json';
const SHA256_HEX_RE = /^[a-f0-9]{64}$/;
const PG_URL_RE = /postgres(?:ql)?:\/\/[^\s'"]+/gi;

export const SNAPSHOT_REQUIRED_FIELDS = Object.freeze([
  'snapshot_id',
  'custody_manifest_digest',
  'storage_reference',
  'retention_policy',
  'signer',
  'previous_snapshot_hash',
  'operator_signoff',
  'snapshot_hash',
]);

const FORBIDDEN_KEYS = new Set([
  'authorization',
  'body',
  'ciphertext',
  'connection_string',
  'credential',
  'customer_payload',
  'database_dump',
  'database_url',
  'dump',
  'dump_contents',
  'encrypted_blob',
  'encrypted_payload',
  'envelope_ciphertext',
  'evidence_body',
  'evidence_payload',
  'headers',
  'log',
  'log_line',
  'logs',
  'packet_payload',
  'password',
  'payload',
  'raw_body',
  'raw_evidence',
  'raw_headers',
  'raw_log',
  'raw_packet',
  'secret',
  'sql_dump',
  'token',
]);

function normalizeKey(key) {
  return key
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function hasValue(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string' && value.trim() === '') return false;
  if (Array.isArray(value) && value.length === 0) return false;
  return true;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function collectForbiddenFields(value, fieldPath = '') {
  if (value === null || value === undefined || typeof value !== 'object') return [];
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectForbiddenFields(entry, `${fieldPath}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = fieldPath ? `${fieldPath}.${key}` : key;
    const normalized = normalizeKey(key);
    if (
      FORBIDDEN_KEYS.has(normalized)
      || normalized.startsWith('raw_')
      || normalized.endsWith('_ciphertext')
      || normalized.includes('customer_payload')
    ) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenFields(nested, keyPath));
  }
  return findings;
}

function collectForbiddenStringPatterns(value, fieldPath = '') {
  if (value === null || value === undefined) return [];
  if (typeof value === 'string') {
    const findings = [];
    if (PG_URL_RE.test(value)) {
      PG_URL_RE.lastIndex = 0;
      findings.push(`${fieldPath}:database_url_pattern`);
    }
    return findings;
  }
  if (Array.isArray(value)) {
    return value.flatMap((entry, index) => collectForbiddenStringPatterns(entry, `${fieldPath}[${index}]`));
  }
  if (typeof value === 'object') {
    return Object.entries(value).flatMap(([key, nested]) =>
      collectForbiddenStringPatterns(nested, fieldPath ? `${fieldPath}.${key}` : key),
    );
  }
  return [];
}

/**
 * @param {Record<string, unknown>} snapshot
 */
export function computeSnapshotHash(snapshot) {
  const body = { ...snapshot };
  delete body.snapshot_hash;
  return sha256CanonicalJson(body);
}

function validateRetentionPolicy(policy, index) {
  const gaps = [];
  const prefix = `snapshots[${index}].retention_policy`;
  if (!isObject(policy)) {
    gaps.push(`${prefix}:missing`);
    return gaps;
  }
  if (!Object.prototype.hasOwnProperty.call(policy, 'legal_hold')) {
    gaps.push(`${prefix}.legal_hold:missing`);
  } else if (typeof policy.legal_hold !== 'boolean') {
    gaps.push(`${prefix}.legal_hold:invalid_type`);
  }
  for (const field of ['metadata_retention_days', 'report_days', 'audit_log_days']) {
    const value = Number(policy[field]);
    if (!Number.isInteger(value) || value < 1) {
      gaps.push(`${prefix}.${field}:invalid`);
    }
  }
  return gaps;
}

function validateSigner(signer, index) {
  const gaps = [];
  const prefix = `snapshots[${index}].signer`;
  if (!isObject(signer)) {
    gaps.push(`${prefix}:missing`);
    return gaps;
  }
  for (const field of ['key_reference', 'algorithm', 'signature_reference']) {
    if (!hasValue(signer[field])) {
      gaps.push(`${prefix}.${field}:missing`);
    }
  }
  if (hasValue(signer.signature) && typeof signer.signature !== 'string') {
    gaps.push(`${prefix}.signature:invalid_type`);
  }
  return gaps;
}

/**
 * @param {{
 *   tenantId: string,
 *   snapshot: Record<string, unknown>,
 *   index: number,
 *   env?: NodeJS.ProcessEnv,
 * }} input
 */
export function validateSnapshotSignature(input) {
  const gaps = [];
  const prefix = `snapshots[${input.index}].signer`;
  const signer = input.snapshot?.signer;
  if (!isObject(signer) || !hasValue(signer.signature)) {
    return gaps;
  }
  const verification = verifyCustodyManifestSignature({
    tenantId: input.tenantId,
    custodyManifestDigest: String(input.snapshot.custody_manifest_digest ?? ''),
    signer,
    env: input.env,
  });
  if (verification.ok) {
    return gaps;
  }
  if (verification.error === 'unknown_signing_key_reference' || verification.error === 'invalid_signing_key_config') {
    gaps.push(`${prefix}:verification_unconfigured`);
    return gaps;
  }
  gaps.push(`${prefix}.signature:${verification.error}`);
  return gaps;
}

function validateOperatorSignoff(signoff, index) {
  const gaps = [];
  const prefix = `snapshots[${index}].operator_signoff`;
  if (!isObject(signoff)) {
    gaps.push(`${prefix}:missing`);
    return gaps;
  }
  for (const field of ['operator', 'signed_at', 'signoff_reference']) {
    if (!hasValue(signoff[field])) {
      gaps.push(`${prefix}.${field}:missing`);
    }
  }
  return gaps;
}

function validateSnapshotEntry(snapshot, index, tenantId, env = process.env) {
  const gaps = [];
  const prefix = `snapshots[${index}]`;
  if (!isObject(snapshot)) {
    gaps.push(`${prefix}:invalid`);
    return gaps;
  }
  for (const field of SNAPSHOT_REQUIRED_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(snapshot, field)) {
      gaps.push(`${prefix}.${field}:missing`);
    }
  }
  if (!hasValue(snapshot.snapshot_id)) {
    gaps.push(`${prefix}.snapshot_id:empty`);
  }
  const digest = String(snapshot.custody_manifest_digest ?? '');
  if (!SHA256_HEX_RE.test(digest)) {
    gaps.push(`${prefix}.custody_manifest_digest:invalid`);
  }
  if (!hasValue(snapshot.storage_reference)) {
    gaps.push(`${prefix}.storage_reference:empty`);
  }
  gaps.push(...validateRetentionPolicy(snapshot.retention_policy, index));
  gaps.push(...validateSigner(snapshot.signer, index));
  if (hasValue(tenantId)) {
    gaps.push(...validateSnapshotSignature({ tenantId, snapshot, index, env }));
  }
  gaps.push(...validateOperatorSignoff(snapshot.operator_signoff, index));

  const declaredHash = String(snapshot.snapshot_hash ?? '');
  if (!SHA256_HEX_RE.test(declaredHash)) {
    gaps.push(`${prefix}.snapshot_hash:invalid`);
  } else if (isObject(snapshot)) {
    try {
      const expected = computeSnapshotHash(snapshot);
      if (declaredHash !== expected) {
        gaps.push(`${prefix}.snapshot_hash:mismatch`);
      }
    } catch {
      gaps.push(`${prefix}.snapshot_hash:compute_failed`);
    }
  }

  const prev = snapshot.previous_snapshot_hash;
  if (prev !== null && (typeof prev !== 'string' || !SHA256_HEX_RE.test(prev))) {
    gaps.push(`${prefix}.previous_snapshot_hash:invalid`);
  }
  return gaps;
}

function validateSnapshotChain(snapshots, tenantId, env = process.env) {
  const gaps = [];
  if (!Array.isArray(snapshots) || snapshots.length === 0) {
    gaps.push('snapshots:missing_or_empty');
    return gaps;
  }
  snapshots.forEach((snapshot, index) => {
    gaps.push(...validateSnapshotEntry(snapshot, index, tenantId, env));
  });
  const first = snapshots[0];
  if (isObject(first) && first.previous_snapshot_hash !== null) {
    gaps.push('snapshots[0].previous_snapshot_hash:expected_null');
  }
  for (let i = 1; i < snapshots.length; i += 1) {
    const prevSnap = snapshots[i - 1];
    const curr = snapshots[i];
    if (!isObject(prevSnap) || !isObject(curr)) continue;
    const expectedPrev = String(prevSnap.snapshot_hash ?? '');
    const actualPrev = curr.previous_snapshot_hash;
    if (SHA256_HEX_RE.test(expectedPrev) && actualPrev !== expectedPrev) {
      gaps.push(`snapshots[${i}].previous_snapshot_hash:chain_break`);
    }
  }
  return gaps;
}

/**
 * @param {unknown} batch
 */
export function validateEvidenceSnapshotBatch(batch) {
  const gaps = [];
  if (!isObject(batch)) {
    return {
      ok: false,
      gaps: ['batch:invalid'],
      forbidden_fields: [],
      snapshot_count: 0,
    };
  }
  if (!hasValue(batch.tenant_id)) {
    gaps.push('tenant_id:missing');
  }
  const forbidden_fields = [
    ...new Set([
      ...collectForbiddenFields(batch),
      ...collectForbiddenStringPatterns(batch),
    ]),
  ].sort();

  gaps.push(...validateSnapshotChain(batch.snapshots, batch.tenant_id));

  const ok = gaps.length === 0 && forbidden_fields.length === 0;
  const snapshot_count = Array.isArray(batch.snapshots) ? batch.snapshots.length : 0;
  return { ok, gaps: [...new Set(gaps)].sort(), forbidden_fields, snapshot_count };
}

export function parseArgs(argv = []) {
  const opts = {
    input: null,
    out: DEFAULT_OUT,
    validateOnly: false,
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`evidence-snapshot-manifest: missing value for ${arg}`);
      return argv[i];
    };
    if (arg === '--input') opts.input = next();
    else if (arg === '--out') opts.out = next();
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`evidence-snapshot-manifest: unknown argument ${arg}`);
  }
  if (!opts.help && !opts.input) {
    throw new Error('evidence-snapshot-manifest: --input is required');
  }
  return opts;
}

function readBatchInput(inputPath) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(inputPath, 'utf8'));
  } catch {
    throw new Error(`evidence-snapshot-manifest: input is not valid JSON: ${inputPath}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('evidence-snapshot-manifest: input must be a JSON object');
  }
  return parsed;
}

/**
 * @param {{
 *   batch: Record<string, unknown>,
 *   validation: ReturnType<typeof validateEvidenceSnapshotBatch>,
 *   createdAt?: string,
 * }} input
 */
export function createEvidenceSnapshotManifest(input) {
  const { batch, validation, createdAt } = input;
  if (validation.forbidden_fields.length > 0) {
    throw new Error(
      `batch contains forbidden content: ${validation.forbidden_fields.join(', ')}`,
    );
  }

  const redactedBatch = redactObject(batch);
  const snapshots = Array.isArray(redactedBatch.snapshots) ? redactedBatch.snapshots : [];
  return {
    schema_version: 1,
    artifact_type: 'immutable_evidence_snapshot_manifest',
    created_at: createdAt ?? new Date().toISOString(),
    validation: {
      ok: validation.ok,
      gaps: validation.gaps,
      forbidden_fields: validation.forbidden_fields,
      snapshot_count: validation.snapshot_count,
    },
    summary: {
      tenant_id: redactedBatch.tenant_id ?? null,
      batch_id: redactedBatch.batch_id ?? null,
      snapshots: snapshots.map((snapshot) => ({
        snapshot_id: snapshot?.snapshot_id ?? null,
        custody_manifest_digest: snapshot?.custody_manifest_digest ?? null,
        storage_reference: snapshot?.storage_reference ?? null,
        retention_policy: snapshot?.retention_policy ?? null,
        signer: snapshot?.signer ?? null,
        previous_snapshot_hash: snapshot?.previous_snapshot_hash ?? null,
        snapshot_hash: snapshot?.snapshot_hash ?? null,
        operator_signoff: snapshot?.operator_signoff ?? null,
      })),
    },
    gaps: validation.gaps,
    caveats: [
      'Metadata-only immutable evidence snapshot manifest; no raw payloads, logs, tokens, secrets, database URLs, or ciphertext.',
      'When signer.signature is present, signatures are verified against tenant-scoped key references from ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON (no private keys in-repo).',
      'This utility does not implement external object storage, KMS/HSM signing, or durable immutable archives.',
    ],
  };
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(`Usage: node scripts/evidence-snapshot-manifest.mjs --input batch.json [--out file] [--validate-only]

Validates immutable evidence snapshot batches (custody digests, storage references, retention/legal hold, signer metadata, chain hashes, operator signoff).
Rejects raw evidence payloads, logs, tokens, secrets, database URLs, and ciphertext material.`);
    return 0;
  }

  const batch = readBatchInput(opts.input);
  const validation = validateEvidenceSnapshotBatch(batch);
  const manifest = createEvidenceSnapshotManifest({ batch, validation });

  if (opts.validateOnly) {
    console.log(
      `evidence-snapshot-manifest: ${validation.ok ? 'ok' : 'failed'} (snapshots=${validation.snapshot_count}, gaps=${validation.gaps.length})`,
    );
    return validation.ok ? 0 : 1;
  }

  mkdirSync(path.dirname(path.resolve(opts.out)), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`evidence-snapshot-manifest: wrote ${opts.out}`);
  return validation.ok ? 0 : 1;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`evidence-snapshot-manifest: ${redactString(err.message)}`);
      process.exit(1);
    },
  );
}