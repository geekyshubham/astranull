import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { getCheckById } from '../../src/contracts/checks.mjs';
import {
  buildWafProductCatalogSeedRows,
  classifyWafProductFromSignals,
  enrichProbeMetadataWithWafCatalog,
  getWafProductCatalogEntries,
  getWafProductCatalogManifest,
  listWafProductCatalogEntries,
  loadWafProductCatalogDocument,
  seedWafProductsIfEmpty,
  summarizeWafProductCatalog,
  validateWafProductCatalogDocument,
  validateWafProductCatalogEntry,
  WAF_CATALOG_REGRESSION_FIXTURES,
  WAF_FINGERPRINT_PROBE_CHECK_ID,
  WAF_PRODUCT_CATALOG_MIN_ENTRIES,
  wafFingerprintProbeEvidenceFields,
} from '../../src/lib/wafProductCatalog.mjs';
import { simulateProbeResult } from '../../src/services/probeStub.mjs';
import {
  parseSeedWafProductCatalogArgs,
  runSeedWafProductCatalog,
} from '../../scripts/seed-waf-product-catalog.mjs';
import {
  parseValidateWafProductCatalogArgs,
  runValidateWafProductCatalog,
} from '../../scripts/validate-waf-product-catalog.mjs';

describe('WAF product catalog seed', () => {
  it('loads 50+ metadata-only catalog entries from bundled JSON', () => {
    const document = loadWafProductCatalogDocument();
    const validation = validateWafProductCatalogDocument(document);
    assert.equal(validation.ok, true, validation.errors?.join('; '));
    assert.ok(document.entries.length >= WAF_PRODUCT_CATALOG_MIN_ENTRIES);
    assert.equal(document.manifest.entry_count, document.entries.length);
  });

  it('validates schema and safety policy via operator CLI', () => {
    const summary = runValidateWafProductCatalog(null, {
      readFile: (filePath) => readFileSync(filePath, 'utf8'),
    });
    assert.equal(summary.ok, true);
    assert.ok(summary.entry_count >= WAF_PRODUCT_CATALOG_MIN_ENTRIES);
  });

  it('summarizes catalog breadth milestones', () => {
    const products = buildWafProductCatalogSeedRows();
    const summary = summarizeWafProductCatalog(products);
    assert.equal(summary.entry_count, products.length);
    assert.equal(summary.total_products, products.length);
    assert.equal(summary.min_entries_met, products.length >= 50);
    assert.equal(summary.breadth_target_met, products.length >= 50);
    assert.ok(summary.unique_vendors >= 15);
    assert.ok(summary.catalog_version);
  });

  it('covers CDN, cloud-native, appliance, and reverse-proxy deployment types', () => {
    const types = new Set(listWafProductCatalogEntries().map((entry) => entry.deployment_type));
    for (const expected of ['cdn', 'cloud_native', 'appliance', 'reverse_proxy']) {
      assert.ok(types.has(expected), `missing deployment_type ${expected}`);
    }
  });

  it('seeds dev-json store idempotently from JSON catalog', () => {
    const store = { wafProducts: [] };
    assert.equal(seedWafProductsIfEmpty(store), true);
    assert.ok(store.wafProducts.length >= 50);
    assert.equal(seedWafProductsIfEmpty(store), false);
    assert.equal(store.wafProducts.length, getWafProductCatalogEntries().length);
  });

  it('rejects unsafe catalog entries with forbidden keys or exploit-like patterns', () => {
    const forbiddenKeyEntry = {
      id: 'waf_prod_bad',
      vendor: 'bad',
      product: 'Bad WAF',
      deployment_type: 'custom',
      header_name_patterns: ['^x-safe$'],
      cookie_name_patterns: [],
      dns_patterns: [],
      block_page_signature_ids: ['block_sig_bad_v1'],
      connector_provider_ids: [],
      fingerprint_version: '2026.07.01',
      enabled: true,
      exploit_payload: 'blocked',
    };
    const forbiddenErrors = validateWafProductCatalogEntry(forbiddenKeyEntry, 0);
    assert.ok(forbiddenErrors.some((msg) => msg.includes('forbidden key')));

    const { exploit_payload: _ignored, ...safeBase } = forbiddenKeyEntry;
    const unsafePatternEntry = {
      ...safeBase,
      header_name_patterns: ['<script>alert(1)</script>'],
    };
    const patternErrors = validateWafProductCatalogEntry(unsafePatternEntry, 0);
    assert.ok(patternErrors.some((msg) => msg.includes('unsafe exploit-like content')));
  });

  it('classifies metadata-only regression fixtures', () => {
    const cloudflare = classifyWafProductFromSignals(WAF_CATALOG_REGRESSION_FIXTURES.metadata_only_signals);
    assert.equal(cloudflare.best?.vendor, 'cloudflare');
    assert.ok(cloudflare.waf_present);

    const conflict = classifyWafProductFromSignals(WAF_CATALOG_REGRESSION_FIXTURES.conflicting_vendor_signals);
    assert.equal(conflict.conflicting_vendor_signals, true);

    const cdnOnly = classifyWafProductFromSignals(WAF_CATALOG_REGRESSION_FIXTURES.cdn_without_waf);
    assert.equal(cdnOnly.cdn_detected, true);
    assert.equal(cdnOnly.waf_validated, false);
  });

  it('attaches catalog version to fingerprint probe evidence metadata', () => {
    const manifest = getWafProductCatalogManifest();
    const fields = wafFingerprintProbeEvidenceFields(WAF_FINGERPRINT_PROBE_CHECK_ID);
    assert.equal(fields.waf_fingerprint_catalog_version, manifest.catalog_version);
    assert.equal(fields.waf_fingerprint_catalog_entry_count, manifest.entry_count);

    const check = getCheckById(WAF_FINGERPRINT_PROBE_CHECK_ID);
    const probe = simulateProbeResult(check, { id: 'tgt_1', value: 'origin.test' });
    assert.equal(probe.metadata.waf_fingerprint_catalog_version, manifest.catalog_version);

    const enriched = enrichProbeMetadataWithWafCatalog({ status_code: 403 }, 'waf.marker_rule.safe');
    assert.equal(enriched.waf_fingerprint_catalog_version, undefined);
  });

  it('parses operator CLI args and supports dry-run seed summary', async () => {
    assert.deepEqual(parseValidateWafProductCatalogArgs(['node', 'script', '--json']), {
      catalogFile: null,
      json: true,
      help: false,
    });
    assert.deepEqual(parseSeedWafProductCatalogArgs(['node', 'script', '--dry-run']), {
      catalogFile: null,
      dryRun: true,
      out: null,
      help: false,
    });

    const dryRun = await runSeedWafProductCatalog(
      { ASTRANULL_NO_PERSIST: '1' },
      { dryRun: true },
      { readFile: (filePath) => readFileSync(filePath, 'utf8') },
    );
    assert.equal(dryRun.dry_run, true);
    assert.ok(dryRun.entry_count >= WAF_PRODUCT_CATALOG_MIN_ENTRIES);
  });
});