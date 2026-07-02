#!/usr/bin/env node
import crypto from 'node:crypto';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');

export const MANIFEST_VERSION = 1;
const SAFE_LABEL = /^[a-zA-Z0-9._-]{1,64}$/;

export function sha256Hex(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

export function parseBackupCliArgs(argv) {
  let source = path.join(ROOT, '.data', 'astranull-dev.json');
  let out = path.join(ROOT, '.data', 'backups');
  let label = null;

  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--source') {
      source = argv[i + 1] ?? '';
      i += 1;
    } else if (arg === '--out') {
      out = argv[i + 1] ?? '';
      i += 1;
    } else if (arg === '--label') {
      label = argv[i + 1] ?? '';
      i += 1;
    } else if (arg === '-h' || arg === '--help') {
      console.log(`Usage: node scripts/backup-dev-store.mjs [--source <path>] [--out <dir>] [--label <safe-label>]

Creates a timestamped copy of the developer-validation JSON store and an integrity manifest.`);
      process.exit(0);
    } else {
      throw new Error(`backup-dev-store: unknown argument ${arg}`);
    }
  }

  if (!source) {
    throw new Error('backup-dev-store: --source requires a value');
  }
  if (!out) {
    throw new Error('backup-dev-store: --out requires a value');
  }
  if (label !== null && !SAFE_LABEL.test(label)) {
    throw new Error('backup-dev-store: --label must match [a-zA-Z0-9._-] (max 64 chars)');
  }

  return {
    source: path.resolve(source),
    out: path.resolve(out),
    label,
  };
}

function timestampForFilename(date = new Date()) {
  return date.toISOString().replace(/[:.]/g, '-');
}

/**
 * @param {{ source: string, out: string, label: string | null, now?: Date }} options
 */
export function backupDevStore(options) {
  const { source, out, label, now = new Date() } = options;

  if (!existsSync(source)) {
    const err = new Error(`backup-dev-store: source not found: ${source}`);
    err.code = 'ENOENT';
    throw err;
  }

  const raw = readFileSync(source);
  try {
    JSON.parse(raw.toString('utf8'));
  } catch {
    throw new Error(`backup-dev-store: source is not valid JSON: ${source}`);
  }

  mkdirSync(out, { recursive: true });

  const base = path.basename(source, path.extname(source)) || 'astranull-dev';
  const backupName = `${base}-${timestampForFilename(now)}.json`;
  const backupPath = path.join(out, backupName);
  copyFileSync(source, backupPath);

  const backupBytes = readFileSync(backupPath);
  const checksum = sha256Hex(backupBytes);
  const manifest = {
    version: MANIFEST_VERSION,
    created_at: now.toISOString(),
    source,
    backup_file: backupName,
    sha256: checksum,
    bytes: backupBytes.length,
    label,
  };
  const manifestPath = `${backupPath}.manifest.json`;
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');

  return { backupPath, manifestPath, manifest };
}

function main() {
  try {
    const opts = parseBackupCliArgs(process.argv);
    const { backupPath, manifestPath, manifest } = backupDevStore(opts);
    console.log('backup-dev-store: ok');
    console.log(`  backup: ${backupPath}`);
    console.log(`  manifest: ${manifestPath}`);
    console.log(`  sha256: ${manifest.sha256}`);
    console.log(`  bytes: ${manifest.bytes}`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(message);
    process.exitCode = 1;
  }
}

const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main();
}