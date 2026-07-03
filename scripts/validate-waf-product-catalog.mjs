#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  getWafProductCatalogManifest,
  resolveWafProductCatalogPath,
  validateWafProductCatalogDocument,
  WAF_PRODUCT_CATALOG_MIN_ENTRIES,
} from '../src/lib/wafProductCatalog.mjs';

const __filename = fileURLToPath(import.meta.url);

const USAGE = `validate-waf-product-catalog: schema + safety policy validation for WAF fingerprint catalog.

Options:
  --catalog-file <path>   Catalog JSON path (default: db/seeds/waf-product-catalog.json)
  --json                  Emit machine-readable JSON summary on success
  --help                  Show this message
`;

/**
 * @param {string[]} argv
 */
export function parseValidateWafProductCatalogArgs(argv) {
  const args = argv.slice(2);
  /** @type {{ catalogFile: string | null, json: boolean, help: boolean }} */
  const parsed = {
    catalogFile: null,
    json: false,
    help: false,
  };

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') {
      parsed.help = true;
      continue;
    }
    if (arg === '--json') {
      parsed.json = true;
      continue;
    }
    if (arg === '--catalog-file') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('validate-waf-product-catalog: --catalog-file requires a path.');
      }
      parsed.catalogFile = value;
      i += 1;
      continue;
    }
    throw new Error(`validate-waf-product-catalog: unknown argument "${arg}".`);
  }

  return parsed;
}

/**
 * @param {string | null} catalogFile
 * @param {{ readFile?: (path: string) => string }} [deps]
 */
export function runValidateWafProductCatalog(catalogFile, deps = {}) {
  const readFile = deps.readFile ?? ((filePath) => readFileSync(filePath, 'utf8'));
  const catalogPath = resolveWafProductCatalogPath(catalogFile ?? undefined);
  const document = JSON.parse(readFile(catalogPath));
  const validation = validateWafProductCatalogDocument(document);
  if (!validation.ok) {
    const err = new Error(validation.errors.join('\n'));
    err.code = 'waf_catalog_validation_failed';
    err.errors = validation.errors;
    throw err;
  }

  const manifest = getWafProductCatalogManifest(catalogPath);
  const deploymentCounts = {};
  for (const entry of document.entries) {
    const key = String(entry.deployment_type ?? 'unknown');
    deploymentCounts[key] = (deploymentCounts[key] ?? 0) + 1;
  }

  return {
    ok: true,
    catalog_path: catalogPath,
    catalog_version: manifest.catalog_version,
    fingerprint_version: manifest.fingerprint_version,
    entry_count: manifest.entry_count,
    min_entry_count: WAF_PRODUCT_CATALOG_MIN_ENTRIES,
    deployment_type_counts: deploymentCounts,
    checksum_sha256: manifest.checksum_sha256,
  };
}

function main() {
  const parsed = parseValidateWafProductCatalogArgs(process.argv);
  if (parsed.help) {
    process.stdout.write(USAGE);
    return;
  }

  try {
    const summary = runValidateWafProductCatalog(parsed.catalogFile);
    if (parsed.json) {
      process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
      return;
    }
    process.stdout.write('validate-waf-product-catalog: ok\n');
    process.stdout.write(`  catalog_version: ${summary.catalog_version}\n`);
    process.stdout.write(`  fingerprint_version: ${summary.fingerprint_version}\n`);
    process.stdout.write(`  entry_count: ${summary.entry_count}\n`);
    process.stdout.write(`  checksum_sha256: ${summary.checksum_sha256 ?? '(none)'}\n`);
    for (const [deploymentType, count] of Object.entries(summary.deployment_type_counts).sort()) {
      process.stdout.write(`  deployment_type.${deploymentType}: ${count}\n`);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`validate-waf-product-catalog: failed\n${message}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  main();
}