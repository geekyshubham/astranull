#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadRuntimeConfig } from '../src/config.mjs';
import { redactDatabaseUrlInMessage } from '../src/lib/pgErrorRedact.mjs';
import {
  getWafProductCatalogEntries,
  getWafProductCatalogManifest,
  mapCatalogEntryToWafProduct,
  resolveWafProductCatalogPath,
  validateWafProductCatalogDocument,
} from '../src/lib/wafProductCatalog.mjs';
import { closePgPool, createPgPool } from '../src/persistence/postgres/pool.mjs';
import { getStore, persistStore } from '../src/store.mjs';
import { runValidateWafProductCatalog } from './validate-waf-product-catalog.mjs';

const __filename = fileURLToPath(import.meta.url);

const USAGE = `seed-waf-product-catalog: idempotent seed of global waf_products catalog rows.

Supports dev-json mode (default) or Postgres mode when ASTRANULL_DATABASE_URL is set.

Options:
  --catalog-file <path>   Catalog JSON path (default: db/seeds/waf-product-catalog.json)
  --dry-run               Validate and summarize without writing
  --out <path>            Write metadata-only JSON summary to this path
  --help                  Show this message
`;

/**
 * @param {string[]} argv
 */
export function parseSeedWafProductCatalogArgs(argv) {
  const args = argv.slice(2);
  /** @type {{ catalogFile: string | null, dryRun: boolean, out: string | null, help: boolean }} */
  const parsed = {
    catalogFile: null,
    dryRun: false,
    out: null,
    help: false,
  };

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') {
      parsed.help = true;
      continue;
    }
    if (arg === '--dry-run') {
      parsed.dryRun = true;
      continue;
    }
    if (arg === '--catalog-file') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('seed-waf-product-catalog: --catalog-file requires a path.');
      }
      parsed.catalogFile = value;
      i += 1;
      continue;
    }
    if (arg === '--out') {
      const value = args[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('seed-waf-product-catalog: --out requires a path.');
      }
      parsed.out = value;
      i += 1;
      continue;
    }
    throw new Error(`seed-waf-product-catalog: unknown argument "${arg}".`);
  }

  return parsed;
}

/**
 * @param {ReturnType<typeof mapCatalogEntryToWafProduct>[]} products
 */
export function upsertDevJsonWafProducts(products) {
  const store = getStore();
  const byId = new Map((store.wafProducts ?? []).map((row) => [row.id, row]));
  let inserted = 0;
  let updated = 0;

  for (const product of products) {
    const existing = byId.get(product.id);
    const next = {
      ...product,
      confidence_rules_json: product.confidence_rules_json,
    };
    if (!existing) {
      inserted += 1;
    } else {
      updated += 1;
    }
    byId.set(product.id, next);
  }

  store.wafProducts = [...byId.values()].sort((a, b) => a.id.localeCompare(b.id));
  persistStore();

  return {
    inserted,
    updated,
    total: store.wafProducts.length,
  };
}

/**
 * @param {import('pg').Pool} pool
 * @param {ReturnType<typeof mapCatalogEntryToWafProduct>[]} products
 */
export async function upsertPostgresWafProducts(pool, products) {
  const client = await pool.connect();
  let inserted = 0;
  let updated = 0;

  try {
    await client.query('BEGIN');
    for (const product of products) {
      const result = await client.query(
        `INSERT INTO waf_products (
           id, vendor, product, deployment_type, fingerprint_version, confidence_rules_json, enabled
         ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)
         ON CONFLICT (id) DO UPDATE SET
           vendor = EXCLUDED.vendor,
           product = EXCLUDED.product,
           deployment_type = EXCLUDED.deployment_type,
           fingerprint_version = EXCLUDED.fingerprint_version,
           confidence_rules_json = EXCLUDED.confidence_rules_json,
           enabled = EXCLUDED.enabled
         RETURNING (xmax = 0) AS inserted`,
        [
          product.id,
          product.vendor,
          product.product,
          product.deployment_type,
          product.fingerprint_version,
          JSON.stringify(product.confidence_rules_json ?? {}),
          product.enabled,
        ],
      );
      const rowInserted = result.rows[0]?.inserted === true;
      if (rowInserted) inserted += 1;
      else updated += 1;
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }

  const countResult = await pool.query('SELECT COUNT(*)::int AS total FROM waf_products');
  return {
    inserted,
    updated,
    total: countResult.rows[0]?.total ?? products.length,
  };
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {{ catalogFile?: string | null, dryRun?: boolean }} parsed
 * @param {{ readFile?: (path: string) => string, createPool?: typeof createPgPool }} [deps]
 */
export async function runSeedWafProductCatalog(env, parsed, deps = {}) {
  const readFile = deps.readFile ?? ((filePath) => readFileSync(filePath, 'utf8'));
  const catalogPath = resolveWafProductCatalogPath(parsed.catalogFile ?? undefined);
  const document = JSON.parse(readFile(catalogPath));
  const validation = validateWafProductCatalogDocument(document);
  if (!validation.ok) {
    const err = new Error(validation.errors.join('\n'));
    err.code = 'waf_catalog_validation_failed';
    err.errors = validation.errors;
    throw err;
  }

  const manifest = getWafProductCatalogManifest(catalogPath);
  const products = getWafProductCatalogEntries(catalogPath);

  if (parsed.dryRun) {
    return {
      mode: env.ASTRANULL_DATABASE_URL ? 'postgres-dry-run' : 'dev-json-dry-run',
      dry_run: true,
      catalog_version: manifest.catalog_version,
      fingerprint_version: manifest.fingerprint_version,
      entry_count: products.length,
      product_ids: products.map((row) => row.id),
    };
  }

  const runtimeConfig = loadRuntimeConfig(env);
  if (runtimeConfig.persistenceMode === 'postgres') {
    const pool = (deps.createPool ?? createPgPool)(env);
    try {
      const counts = await upsertPostgresWafProducts(pool, products);
      return {
        mode: 'postgres',
        catalog_version: manifest.catalog_version,
        fingerprint_version: manifest.fingerprint_version,
        ...counts,
      };
    } finally {
      await closePgPool(pool);
    }
  }

  const counts = upsertDevJsonWafProducts(products);
  return {
    mode: 'dev-json',
    catalog_version: manifest.catalog_version,
    fingerprint_version: manifest.fingerprint_version,
    ...counts,
  };
}

async function main() {
  const parsed = parseSeedWafProductCatalogArgs(process.argv);
  if (parsed.help) {
    process.stdout.write(USAGE);
    return;
  }

  try {
    runValidateWafProductCatalog(parsed.catalogFile);
    const summary = await runSeedWafProductCatalog(process.env, parsed);
    const output = `${JSON.stringify(summary, null, 2)}\n`;
    if (parsed.out) {
      mkdirSync(path.dirname(path.resolve(parsed.out)), { recursive: true });
      writeFileSync(parsed.out, output, 'utf8');
    }
    process.stdout.write(output);
  } catch (err) {
    const message = redactDatabaseUrlInMessage(err instanceof Error ? err.message : String(err));
    process.stderr.write(`seed-waf-product-catalog: ${message}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  main();
}