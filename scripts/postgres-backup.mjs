#!/usr/bin/env node
import { spawnSync as defaultSpawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactDatabaseUrlInMessage } from '../src/lib/pgErrorRedact.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');

export const MANIFEST_VERSION = 1;
export const ARTIFACT_TYPE = 'postgres_backup_manifest';
export const BACKUP_ENCRYPTION_ALGORITHM = 'AES-256-GCM';
export const BACKUP_ENVELOPE_VERSION = 1;

const KEY_BYTES = 32;
const IV_BYTES = 12;
const SAFE_LABEL = /^[a-zA-Z0-9._-]{1,64}$/;
const SHA256_HEX_RE = /^[a-fA-F0-9]{64}$/;
const PG_CUSTOM_DUMP_MAGIC = Buffer.from('PGDMP', 'ascii');

const MANIFEST_FORBIDDEN_KEYS = new Set([
  'auth_tag',
  'authorization',
  'ciphertext',
  'connection_string',
  'credential',
  'database_dump',
  'database_url',
  'dump',
  'dump_contents',
  'encryption_key',
  'iv',
  'password',
  'pg_dump',
  'raw_dump',
  'secret',
  'sql_dump',
  'token',
]);

export function sha256Hex(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function stableStringify(value) {
  if (value === undefined) {
    return 'null';
  }
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => (v === undefined ? 'null' : stableStringify(v))).join(',')}]`;
  }
  const keys = Object.keys(value).sort().filter((k) => value[k] !== undefined);
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`;
}

function serializeAad(aadObject) {
  return Buffer.from(stableStringify(aadObject ?? {}), 'utf8');
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 */
export function resolveDatabaseUrl(env = process.env) {
  const databaseUrl = String(env.ASTRANULL_DATABASE_URL ?? env.DATABASE_URL ?? '').trim();
  if (!databaseUrl) {
    return {
      ok: false,
      message:
        'postgres-backup: DATABASE_URL or ASTRANULL_DATABASE_URL must be set.',
    };
  }
  return { ok: true, databaseUrl };
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {{ required?: boolean }} [options]
 */
export function loadBackupEncryptionKey(env = process.env, { required = true } = {}) {
  const raw = String(env.ASTRANULL_BACKUP_ENCRYPTION_KEY ?? '').trim();
  if (!raw) {
    if (required) {
      throw new Error(
        'postgres-backup: ASTRANULL_BACKUP_ENCRYPTION_KEY must be set for encrypted backups.',
      );
    }
    return null;
  }

  let key;
  if (/^[0-9a-fA-F]{64}$/.test(raw)) {
    key = Buffer.from(raw, 'hex');
  } else {
    key = Buffer.from(raw, 'base64');
  }

  if (key.length !== KEY_BYTES) {
    throw new Error(
      'postgres-backup: ASTRANULL_BACKUP_ENCRYPTION_KEY must be a 32-byte key encoded as base64 or 64-character hex.',
    );
  }
  return key;
}

/**
 * @param {string} databaseUrl
 */
export function parseDatabaseReference(databaseUrl) {
  let parsed;
  try {
    parsed = new URL(databaseUrl);
  } catch {
    throw new Error('postgres-backup: database URL is not a valid connection URI.');
  }
  if (parsed.protocol !== 'postgresql:' && parsed.protocol !== 'postgres:') {
    throw new Error('postgres-backup: database URL must use the postgresql:// scheme.');
  }
  const database = decodeURIComponent(parsed.pathname.replace(/^\//, '') || 'postgres');
  return {
    host: parsed.hostname || 'localhost',
    port: parsed.port ? Number(parsed.port) : 5432,
    database,
  };
}

function normalizeManifestKey(key) {
  return key
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

/**
 * @param {unknown} value
 * @param {string} [fieldPath]
 */
export function collectManifestForbiddenFields(value, fieldPath = '') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return [];
  }
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectManifestForbiddenFields(entry, `${fieldPath}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = fieldPath ? `${fieldPath}.${key}` : key;
    const normalized = normalizeManifestKey(key);
    if (
      MANIFEST_FORBIDDEN_KEYS.has(normalized)
      || normalized.startsWith('raw_')
      || normalized.endsWith('_dump')
      || normalized.includes('database_url')
    ) {
      findings.push(keyPath);
    }
    findings.push(...collectManifestForbiddenFields(nested, keyPath));
  }
  return findings;
}

/**
 * @param {unknown} name
 */
export function isSimpleBackupFilename(name) {
  if (typeof name !== 'string' || name.length === 0) {
    return false;
  }
  if (name.includes('..')) {
    return false;
  }
  if (name.includes('/') || name.includes('\\')) {
    return false;
  }
  if (path.isAbsolute(name)) {
    return false;
  }
  return path.basename(name) === name;
}

/**
 * @param {Record<string, unknown>} manifest
 */
export function validatePostgresBackupManifestFields(manifest) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw new Error('postgres-backup: manifest must be a JSON object');
  }
  if (manifest.version !== MANIFEST_VERSION) {
    throw new Error(`postgres-backup: manifest version must be ${MANIFEST_VERSION}`);
  }
  if (manifest.artifact_type !== ARTIFACT_TYPE) {
    throw new Error(`postgres-backup: manifest artifact_type must be ${ARTIFACT_TYPE}`);
  }
  if (!isSimpleBackupFilename(manifest.backup_file)) {
    throw new Error(
      'postgres-backup: manifest backup_file must be a simple filename (no path separators or ..)',
    );
  }
  if (typeof manifest.sha256 !== 'string' || !SHA256_HEX_RE.test(manifest.sha256)) {
    throw new Error('postgres-backup: manifest sha256 must be a 64-character hex digest');
  }
  if (!Number.isInteger(manifest.bytes) || manifest.bytes < 0) {
    throw new Error('postgres-backup: manifest bytes must be a nonnegative integer');
  }
  if (
    manifest.plaintext_sha256 !== undefined
    && manifest.plaintext_sha256 !== null
    && (typeof manifest.plaintext_sha256 !== 'string' || !SHA256_HEX_RE.test(manifest.plaintext_sha256))
  ) {
    throw new Error('postgres-backup: manifest plaintext_sha256 must be a 64-character hex digest');
  }
  if (!manifest.database_reference || typeof manifest.database_reference !== 'object') {
    throw new Error('postgres-backup: manifest database_reference is required');
  }
  const ref = manifest.database_reference;
  if (typeof ref.host !== 'string' || !ref.host) {
    throw new Error('postgres-backup: manifest database_reference.host is required');
  }
  if (typeof ref.database !== 'string' || !ref.database) {
    throw new Error('postgres-backup: manifest database_reference.database is required');
  }
  if (!Number.isInteger(ref.port) || ref.port <= 0) {
    throw new Error('postgres-backup: manifest database_reference.port must be a positive integer');
  }
  if (!manifest.encryption || typeof manifest.encryption !== 'object') {
    throw new Error('postgres-backup: manifest encryption metadata is required');
  }
  if (manifest.encryption.algorithm !== BACKUP_ENCRYPTION_ALGORITHM) {
    throw new Error(`postgres-backup: manifest encryption.algorithm must be ${BACKUP_ENCRYPTION_ALGORITHM}`);
  }
  if (manifest.encryption.key_reference !== 'env:ASTRANULL_BACKUP_ENCRYPTION_KEY') {
    throw new Error(
      'postgres-backup: manifest encryption.key_reference must be env:ASTRANULL_BACKUP_ENCRYPTION_KEY',
    );
  }
  const forbidden = [...new Set(collectManifestForbiddenFields(manifest))].sort();
  if (forbidden.length > 0) {
    throw new Error(
      `postgres-backup: manifest contains forbidden fields: ${forbidden.join(', ')}`,
    );
  }
}

/**
 * @param {Buffer} plaintext
 * @param {Buffer} key
 * @param {Record<string, unknown>} aadObject
 */
export function encryptBackupPayload(plaintext, key, aadObject) {
  if (!key || key.length !== KEY_BYTES) {
    throw new Error('postgres-backup: backup encryption key must be 32 bytes.');
  }
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(serializeAad(aadObject));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    version: BACKUP_ENVELOPE_VERSION,
    algorithm: BACKUP_ENCRYPTION_ALGORITHM,
    iv: iv.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    auth_tag: authTag.toString('base64'),
    created_at: new Date().toISOString(),
  };
}

/**
 * @param {{ version: number, algorithm: string, iv: string, ciphertext: string, auth_tag: string }} envelope
 * @param {Buffer} key
 * @param {Record<string, unknown>} aadObject
 */
export function decryptBackupPayload(envelope, key, aadObject) {
  if (
    !envelope
    || envelope.version !== BACKUP_ENVELOPE_VERSION
    || envelope.algorithm !== BACKUP_ENCRYPTION_ALGORITHM
  ) {
    throw new Error('postgres-backup: unsupported or invalid backup envelope.');
  }
  if (!key || key.length !== KEY_BYTES) {
    throw new Error('postgres-backup: backup encryption key must be 32 bytes.');
  }
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(envelope.iv, 'base64'),
  );
  decipher.setAAD(serializeAad(aadObject));
  decipher.setAuthTag(Buffer.from(envelope.auth_tag, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
    decipher.final(),
  ]);
}

export function parsePostgresBackupCliArgs(argv) {
  let out = path.join(ROOT, '.data', 'backups', 'postgres');
  let label = null;

  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--out') {
      out = argv[i + 1] ?? '';
      i += 1;
    } else if (arg === '--label') {
      label = argv[i + 1] ?? '';
      i += 1;
    } else if (arg === '-h' || arg === '--help') {
      console.log(`Usage: node scripts/postgres-backup.mjs [--out <dir>] [--label <safe-label>]

Creates an encrypted pg_dump custom-format backup and a metadata-only integrity manifest.
Requires DATABASE_URL or ASTRANULL_DATABASE_URL and ASTRANULL_BACKUP_ENCRYPTION_KEY.`);
      process.exit(0);
    } else {
      throw new Error(`postgres-backup: unknown argument ${arg}`);
    }
  }

  if (!out) {
    throw new Error('postgres-backup: --out requires a value');
  }
  if (label !== null && !SAFE_LABEL.test(label)) {
    throw new Error('postgres-backup: --label must match [a-zA-Z0-9._-] (max 64 chars)');
  }

  return {
    out: path.resolve(out),
    label,
  };
}

function timestampForFilename(date = new Date()) {
  return date.toISOString().replace(/[:.]/g, '-');
}

/**
 * @param {string} databaseUrl
 * @param {{ spawnFn?: typeof defaultSpawnSync }} [options]
 */
export function runPgDump(databaseUrl, options = {}) {
  const spawnFn = options.spawnFn ?? defaultSpawnSync;
  const result = spawnFn(
    'pg_dump',
    ['--format=custom', '--no-owner', '--no-acl', `--dbname=${databaseUrl}`],
    { encoding: 'buffer', maxBuffer: 64 * 1024 * 1024 },
  );
  if (result.error) {
    const err = new Error(`postgres-backup: pg_dump failed: ${result.error.message}`);
    err.code = 'PG_DUMP_FAILED';
    throw err;
  }
  if (result.status !== 0) {
    const stderr = Buffer.isBuffer(result.stderr)
      ? result.stderr.toString('utf8')
      : String(result.stderr ?? '');
    const err = new Error(`postgres-backup: pg_dump exited ${result.status}: ${stderr.trim()}`);
    err.code = 'PG_DUMP_FAILED';
    throw err;
  }
  const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.from(result.stdout ?? '');
  if (stdout.length === 0) {
    throw new Error('postgres-backup: pg_dump produced empty output');
  }
  return stdout;
}

/**
 * @param {{
 *   databaseUrl: string,
 *   encryptionKey: Buffer,
 *   out: string,
 *   label: string | null,
 *   now?: Date,
 *   spawnFn?: typeof defaultSpawnSync,
 *   dumpFn?: (databaseUrl: string) => Buffer,
 * }} options
 */
export function backupPostgres(options) {
  const {
    databaseUrl,
    encryptionKey,
    out,
    label,
    now = new Date(),
    spawnFn,
    dumpFn,
  } = options;

  const databaseReference = parseDatabaseReference(databaseUrl);
  const plaintext = dumpFn ? dumpFn(databaseUrl) : runPgDump(databaseUrl, { spawnFn });
  const plaintextSha256 = sha256Hex(plaintext);

  mkdirSync(out, { recursive: true });

  const backupName = `postgres-${timestampForFilename(now)}.dump.enc`;
  const backupPath = path.join(out, backupName);
  const aad = {
    artifact_type: ARTIFACT_TYPE,
    backup_file: backupName,
    created_at: now.toISOString(),
    database_reference: databaseReference,
  };
  const envelope = encryptBackupPayload(plaintext, encryptionKey, aad);
  const backupBytes = Buffer.from(`${JSON.stringify(envelope)}\n`, 'utf8');
  writeFileSync(backupPath, backupBytes);

  const checksum = sha256Hex(backupBytes);
  const manifest = {
    version: MANIFEST_VERSION,
    artifact_type: ARTIFACT_TYPE,
    created_at: now.toISOString(),
    backup_file: backupName,
    sha256: checksum,
    plaintext_sha256: plaintextSha256,
    bytes: backupBytes.length,
    label,
    database_reference: databaseReference,
    dump_format: 'pg_custom',
    encryption: {
      algorithm: BACKUP_ENCRYPTION_ALGORITHM,
      key_reference: 'env:ASTRANULL_BACKUP_ENCRYPTION_KEY',
      envelope_version: BACKUP_ENVELOPE_VERSION,
    },
  };
  validatePostgresBackupManifestFields(manifest);

  const manifestPath = `${backupPath}.manifest.json`;
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');

  return { backupPath, manifestPath, manifest, plaintextBytes: plaintext.length };
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {{ out: string, label: string | null }} cli
 */
export function resolvePostgresBackupConfig(env, cli) {
  const database = resolveDatabaseUrl(env);
  if (!database.ok) {
    return database;
  }
  try {
    loadBackupEncryptionKey(env, { required: true });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, message };
  }
  return {
    ok: true,
    databaseUrl: database.databaseUrl,
    out: cli.out,
    label: cli.label,
  };
}

function main() {
  try {
    const cli = parsePostgresBackupCliArgs(process.argv);
    const config = resolvePostgresBackupConfig(process.env, cli);
    if (!config.ok) {
      console.error(config.message);
      process.exitCode = 1;
      return;
    }

    const encryptionKey = loadBackupEncryptionKey(process.env, { required: true });
    const { backupPath, manifestPath, manifest } = backupPostgres({
      databaseUrl: config.databaseUrl,
      encryptionKey,
      out: config.out,
      label: config.label,
    });

    console.log('postgres-backup: ok');
    console.log(`  backup: ${backupPath}`);
    console.log(`  manifest: ${manifestPath}`);
    console.log(`  sha256: ${manifest.sha256}`);
    console.log(`  plaintext_sha256: ${manifest.plaintext_sha256}`);
    console.log(`  bytes: ${manifest.bytes}`);
    console.log(`  database: ${manifest.database_reference.host}/${manifest.database_reference.database}`);
  } catch (err) {
    const message = redactDatabaseUrlInMessage(err, process.env);
    console.error(message);
    process.exitCode = 1;
  }
}

const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main();
}