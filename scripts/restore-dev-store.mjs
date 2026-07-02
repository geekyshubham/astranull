#!/usr/bin/env node
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256Hex } from './backup-dev-store.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');

const SHA256_HEX_RE = /^[a-fA-F0-9]{64}$/;

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
 * @param {{ backup_file: unknown, sha256: unknown, bytes?: unknown }} manifest
 */
export function validateManifestIntegrityFields(manifest) {
  if (!isSimpleBackupFilename(manifest.backup_file)) {
    throw new Error(
      'restore-dev-store: manifest backup_file must be a simple filename (no path separators or ..)',
    );
  }
  if (typeof manifest.sha256 !== 'string' || !SHA256_HEX_RE.test(manifest.sha256)) {
    throw new Error(
      'restore-dev-store: manifest sha256 must be a 64-character hex digest',
    );
  }
  if (manifest.bytes !== undefined && manifest.bytes !== null) {
    if (!Number.isInteger(manifest.bytes) || manifest.bytes < 0) {
      throw new Error('restore-dev-store: manifest bytes must be a nonnegative integer');
    }
  }
}

export function parseRestoreCliArgs(argv) {
  let manifest = '';
  let backup = null;
  let dest = path.join(ROOT, '.data', 'astranull-dev.json');
  let dryRun = false;
  let yes = false;

  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--manifest') {
      manifest = argv[i + 1] ?? '';
      i += 1;
    } else if (arg === '--backup') {
      backup = argv[i + 1] ?? '';
      i += 1;
    } else if (arg === '--dest') {
      dest = argv[i + 1] ?? '';
      i += 1;
    } else if (arg === '--dry-run') {
      dryRun = true;
    } else if (arg === '--yes') {
      yes = true;
    } else if (arg === '-h' || arg === '--help') {
      console.log(`Usage: node scripts/restore-dev-store.mjs --manifest <path> [--backup <path>] [--dest <path>] [--dry-run] [--yes]

Verifies manifest SHA-256 and restores the developer-validation JSON store. Writes require --yes.`);
      process.exit(0);
    } else {
      throw new Error(`restore-dev-store: unknown argument ${arg}`);
    }
  }

  if (!manifest) {
    throw new Error('restore-dev-store: --manifest is required');
  }
  if (!dest) {
    throw new Error('restore-dev-store: --dest requires a value');
  }

  return {
    manifest: path.resolve(manifest),
    backup: backup ? path.resolve(backup) : null,
    dest: path.resolve(dest),
    dryRun,
    yes,
  };
}

function readManifest(manifestPath) {
  if (!existsSync(manifestPath)) {
    throw new Error(`restore-dev-store: manifest not found: ${manifestPath}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(manifestPath, 'utf8'));
  } catch {
    throw new Error(`restore-dev-store: manifest is not valid JSON: ${manifestPath}`);
  }
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('restore-dev-store: manifest must be a JSON object');
  }
  if (!parsed.backup_file || !parsed.sha256) {
    throw new Error('restore-dev-store: manifest missing backup_file or sha256');
  }
  validateManifestIntegrityFields(parsed);
  return parsed;
}

/**
 * @param {{ manifest: string, backup: string | null, dest: string, dryRun: boolean, yes: boolean }} options
 */
export function restoreDevStore(options) {
  const { manifest: manifestPath, dest, dryRun, yes } = options;
  const manifest = readManifest(manifestPath);
  const manifestDir = path.dirname(manifestPath);
  const backupPath =
    options.backup ?? path.join(manifestDir, manifest.backup_file);

  if (!existsSync(backupPath)) {
    throw new Error(`restore-dev-store: backup not found: ${backupPath}`);
  }

  const backupBytes = readFileSync(backupPath);
  if (manifest.bytes !== undefined && manifest.bytes !== null) {
    if (backupBytes.length !== manifest.bytes) {
      throw new Error(
        `restore-dev-store: manifest bytes (${manifest.bytes}) does not match backup length (${backupBytes.length})`,
      );
    }
  }
  const checksum = sha256Hex(backupBytes);
  if (checksum !== manifest.sha256) {
    const err = new Error(
      `restore-dev-store: checksum mismatch (expected ${manifest.sha256}, got ${checksum})`,
    );
    err.code = 'CHECKSUM_MISMATCH';
    throw err;
  }

  try {
    JSON.parse(backupBytes.toString('utf8'));
  } catch {
    throw new Error(`restore-dev-store: backup is not valid JSON: ${backupPath}`);
  }

  if (dryRun) {
    return {
      status: 'dry-run',
      backupPath,
      manifestPath,
      dest,
      sha256: checksum,
      wrote: false,
    };
  }

  if (!yes) {
    const err = new Error('restore-dev-store: refusing to write without --yes (use --dry-run to preview)');
    err.code = 'CONFIRMATION_REQUIRED';
    throw err;
  }

  mkdirSync(path.dirname(dest), { recursive: true });
  writeFileSync(dest, backupBytes);

  return {
    status: 'restored',
    backupPath,
    manifestPath,
    dest,
    sha256: checksum,
    wrote: true,
  };
}

function main() {
  try {
    const opts = parseRestoreCliArgs(process.argv);
    const result = restoreDevStore(opts);
    console.log(`restore-dev-store: ${result.status}`);
    console.log(`  backup: ${result.backupPath}`);
    console.log(`  manifest: ${result.manifestPath}`);
    console.log(`  dest: ${result.dest}`);
    console.log(`  sha256: ${result.sha256}`);
    if (result.wrote) {
      console.log('  wrote: yes');
    } else {
      console.log('  wrote: no');
    }
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